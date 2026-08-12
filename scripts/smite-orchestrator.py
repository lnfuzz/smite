#!/usr/bin/env python3
"""
Smite Fuzzing Campaign Orchestrator

This script automates the execution of parallel fuzzing trials across multiple targets
for rigorous A/B coverage evaluation. It queues jobs, maps cores to trials for strict
CPU isolation via `taskset`, and launches `afl-fuzz` against Nyx sharedirs.

`smitebot` is used for one-time setup steps (`smitebot build` to build Docker workload
images, and `smitebot doctor` to validate the host). Similar to `smitebot start`, this
script handles building `libsmite_ir_mutator.so`, preparing the Nyx sharedir, and
launching `afl-fuzz` with the right strategy flags and environment variables directly.

A live Rich TUI dashboard monitors coverage (Edges and Execs/s) of all active cores in
real-time. Press Ctrl+C to stop scheduling new jobs and safely kill active fuzzers.

Requirements:
    pip install rich
    smitebot (must be available in your PATH: `cargo install --path smitebot`)

Generated Directory Structure:
    The script creates an output directory populated with isolated trial runs based on
    your defined configuration labels:

    <out_dir>/
    ├── .default-seeds/                  # Fallback '\x00' seed (if --seed-dir omitted)
    ├── <label_a>/                       # e.g., 'baseline'
    │   ├── <target_1>/                  # e.g., 'cln'
    │   │   ├── trial-01/
    │   │   │   ├── afl-fuzz.log         # Raw afl-fuzz stdout/stderr for this trial
    │   │   │   ├── sharedir/            # Nyx sharedir (deleted on cleanup)
    │   │   │   └── afl-out/default/     # Fuzzer output (stats, plot_data, bitmap)
    │   │   ├── trial-02/
    │   │   └── ...
    │   └── <target_2>/                  # e.g., 'lnd'
    └── <label_b>/                       # e.g., 'experimental'
        ├── <target_1>/
        └── <target_2>/

Usage:
    python smite-orchestrator.py \
    --out-dir OUT_DIR \
    --configs LABEL:SMITE_DIR[,LABEL:SMITE_DIR...] \
    --scenario SCENARIO \
    --targets TARGET[,TARGET...] \
    --cores CORE[,CORE...] \
    --afl-dir AFL_DIR \
    [--trials N | --trial-ids ID[,ID...]] \
    [--timeout SECONDS] \
    [--seed-dir SEED_DIR]

Examples:
    # Standard 24-hour evaluation (4 isolated cores, 30 trials per target/config)
    python smite-orchestrator.py \
        --out-dir ./eval-results \
        --configs baseline:~/smite,experimental:~/smite-new-mutator \
        --scenario ir \
        --targets cln,lnd,ldk,eclair \
        --cores 0,1,2,3 \
        --afl-dir ~/AFLplusplus

    # Fast exploratory test run (1-hour timeout, 5 trials, with seed corpus)
    python smite-orchestrator.py \
        --out-dir ./eval-results \
        --configs control:~/smite,test:~/smite-new-mutator \
        --scenario ir \
        --targets cln \
        --cores 4,5,6,7,8 \
        --trials 5 \
        --timeout 3600 \
        --afl-dir ~/AFLplusplus \
        --seed-dir ./my_seeds

    # Targeted re-run of specific failed trials (preserves all other data)
    python smite-orchestrator.py \
        --out-dir ./eval-results \
        --configs baseline:~/smite \
        --scenario ir \
        --targets lnd \
        --cores 0,1 \
        --trial-ids 1,15,20 \
        --afl-dir ~/AFLplusplus
"""

import argparse
import collections
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# ────────────────────────────  CONFIGURATION  ────────────────────────────


def testcache_size_mb() -> Optional[int]:
    """Suggested AFL_TESTCACHE_SIZE (MB) from available RAM.

    Mirrors smitebot's conservative thresholds (50/250/500 MB), since
    machines here are shared across several concurrently-fuzzing cores.
    """
    try:
        meminfo = Path("/proc/meminfo").read_text()
    except OSError:
        return None

    for line in meminfo.splitlines():
        if line.startswith("MemAvailable:"):
            try:
                free_mb = int(line.split()[1]) // 1024
            except (IndexError, ValueError):
                return None
            if free_mb > 32_000:
                return 500
            elif free_mb > 8_000:
                return 250
            else:
                return 50
    return None


@dataclass(frozen=True)
class TrialConfig:
    """Immutable configuration and derived path/command resolution for a single
    fuzzing trial."""

    core: int
    label: str
    target: str
    trial_num: int
    scenario: str
    out_dir: Path
    smite_dir: Path
    afl_dir: Path
    timeout: int
    seed_dir: Path

    @property
    def task_name(self) -> str:
        """Human-readable identifier shown in the dashboard and event log."""
        return f"{self.label}/{self.target}/trial-{self.trial_num:02d}"

    @property
    def trial_dir(self) -> Path:
        """Per-trial output directory: <out_dir>/<label>/<target>/trial-NN/"""
        return self.out_dir / self.label / self.target / f"trial-{self.trial_num:02d}"

    @property
    def afl_out_dir(self) -> Path:
        return self.trial_dir / "afl-out"

    @property
    def sharedir(self) -> Path:
        """Nyx snapshot working directory created uniquely for this trial."""
        return self.trial_dir / "sharedir"

    @property
    def image_tag(self) -> str:
        """Docker image tag: smite-<label>-<target>-<scenario>."""
        return f"smite-{self.label}-{self.target}-{self.scenario}"

    @property
    def log_path(self) -> Path:
        """Raw afl-fuzz stdout/stderr for this trial."""
        return self.trial_dir / "afl-fuzz.log"

    @property
    def stats_file(self) -> Path:
        """AFL++ fuzzer_stats file for the default runner, polled by wait_for_boot() and monitor()."""
        return self.afl_out_dir / "default" / "fuzzer_stats"

    @property
    def ir_mutator_path(self) -> Path:
        return self.smite_dir / "target" / "release" / "libsmite_ir_mutator.so"

    def build_afl_cmd(self) -> list[str]:
        """The exact afl-fuzz invocation for a standalone runner."""
        # Fixed power schedule for every standalone trial.
        POWER_SCHEDULE = "explore"
        # Fixed timeout for a single input.
        EXEC_TIMEOUT = 2000  # 2 seconds
        return [
            "taskset",
            "-c",
            str(self.core),
            str(self.afl_dir / "afl-fuzz"),
            "-X",
            "-i",
            str(self.seed_dir),
            "-o",
            str(self.afl_out_dir),
            "-p",
            POWER_SCHEDULE,
            "-V",
            str(self.timeout),
            "-t",
            str(EXEC_TIMEOUT),
            "--",
            str(self.sharedir),
        ]

    def build_afl_env(self) -> dict:
        env = os.environ.copy()
        env.update(
            {
                "AFL_NO_AFFINITY": "1",
                "AFL_NO_UI": "1",
                "AFL_NO_COLOR": "1",
                "AFL_FORKSRV_INIT_TMOUT": "1800000",
                "AFL_HANG_TIMEOUT": "4000",  # 4 seconds
            }
        )
        testcache = testcache_size_mb()
        if testcache:
            env["AFL_TESTCACHE_SIZE"] = str(testcache)

        # Matches smitebot's ir_mutator_envs(): only for scenarios starting with "ir".
        if self.scenario.startswith("ir"):
            env.update(
                {
                    "AFL_CUSTOM_MUTATOR_LIBRARY": str(self.ir_mutator_path),
                    "AFL_CUSTOM_MUTATOR_ONLY": "1",
                    "AFL_FRAMESHIFT_DISABLE": "1",
                }
            )
        return env


# ────────────────────────────  STATE MANAGEMENT  ────────────────────────────


class CampaignState:
    """Thread-safe state shared by every worker thread and the dashboard renderer."""

    def __init__(self, labels: list[str], cores: list[int]):
        self.lock = threading.Lock()
        self.pid_lock = threading.Lock()
        self.shutdown = threading.Event()

        self.start_time = time.time()
        self.active_pids = set()
        self.completed, self.total = 0, 0

        self.sharedir_lock = threading.Lock()

        self.failed_trials = []

        self.events = collections.deque(maxlen=10)
        self.summary = {
            l: {
                "total": 0,
                "finished": 0,
                "in_progress": 0,
                "incomplete": 0,
                "failed": 0,
            }
            for l in labels
        }
        self.workers = {
            c: {
                "task": "Idle",
                "status": "-",
                "color": "dim",
                "is_active": False,
                "execs_sec": 0.0,
                "edges": 0,
                "start_time": 0.0,
            }
            for c in cores
        }

    def log(self, task: str, msg: str, color: str = "white"):
        """Append a timestamped event to the dashboard's recent-events panel."""
        with self.lock:
            self.events.append(
                f"[[cyan]{time.strftime('%H:%M:%S')}[/]] {task} → [{color}]{msg}[/]"
            )

    def update_worker(self, core: int, **kwargs):
        """Merge fields into a single core's dashboard row (task, status, execs/s, ...)."""
        with self.lock:
            self.workers[core].update(kwargs)

    def update_summary(self, label: str, metric: str, delta: int):
        """Apply a signed delta to one summary counter for a label (e.g. 'finished' += 1)."""
        with self.lock:
            self.summary[label][metric] += delta

    def finish_trial(self):
        """Increment the campaign-wide completed-trial counter (used for N/total display)."""
        with self.lock:
            self.completed += 1

    def record_failure(self, task_name: str):
        """Keep a running list of failed trials for the dashboard."""
        with self.lock:
            if task_name not in self.failed_trials:
                self.failed_trials.append(task_name)

    def register_pid(self, pid: int):
        """Track a live fuzzer PID so SIGINT can kill it even mid-trial."""
        with self.pid_lock:
            self.active_pids.add(pid)

    def unregister_pid(self, pid: int):
        with self.pid_lock:
            self.active_pids.discard(pid)


# ────────────────────────────  UI / DASHBOARD  ────────────────────────────


def print_campaign_summary(
    console: Console,
    targets: list[str],
    labels: list[str],
    trials: int,
    cores: list[int],
    state: CampaignState,
    timeout: int,
):
    """Display a structured campaign overview panel before the live dashboard starts."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column(style="white")

    grid.add_row("Targets", str(len(targets)))
    grid.add_row("Configurations", str(len(labels)))
    grid.add_row("Trials per setup", str(trials))
    grid.add_row("Allocated cores", str(len(cores)))
    grid.add_row("Total trials", str(state.total))

    wall_est = (state.total * timeout) / 3600 / len(cores)
    grid.add_row("Estimated wall-clock", f"{wall_est:.1f} hours")

    console.print(Panel(grid, title="Campaign Configuration", border_style="green"))
    console.print()


class DashboardRenderer:
    """Stateless renderer that turns a CampaignState snapshot into a Rich TUI layout."""

    @staticmethod
    def _fmt_duration(s: float) -> str:
        """Format seconds as 'Hh MMm SSs', dropping leading zero units."""
        m, s = divmod(int(s), 60)
        h, m = divmod(m, 60)
        return f"{h}h {m:02d}m {s:02d}s" if h else (f"{m}m {s:02d}s" if m else f"{s}s")

    @classmethod
    def render(cls, state: CampaignState) -> Group:
        """Build the (core table, summary table, event panel) group for one frame."""
        with state.lock:
            w_snap = {w: dict(s) for w, s in state.workers.items()}
            s_snap = {k: dict(v) for k, v in state.summary.items()}
            e_snap = list(state.events)
            f_snap = list(state.failed_trials)
            completed, total = state.completed, state.total

        core_table = Table(
            title=f"Smite Orchestrator ([bold yellow]Parallel Fuzzing Trials[/])  [cyan]{completed}[/]/[cyan]{total}[/]"
            f" trials  Elapsed [cyan]{cls._fmt_duration(time.time() - state.start_time)}[/]  ",
            title_style="bold magenta",
            expand=True,
        )
        for col in ["Core", "Task", "Status", "Elapsed", "Exec/s", "Edges"]:
            core_table.add_column(
                col,
                justify="right" if col not in ("Task", "Status") else "left",
                style="bold cyan" if col == "Core" else None,
            )

        now = time.time()
        for c, s in sorted(w_snap.items()):
            start = s.get("start_time", 0)
            elap = (
                f"{now - start:.0f}s"
                if (start and s["task"] != "Idle" and s["is_active"])
                else "—"
            )
            core_table.add_row(
                f"Core {c}",
                s["task"],
                f"[{s['color']}]{s['status']}[/]",
                elap,
                f"{s['execs_sec']:.0f}" if s["execs_sec"] else "—",
                f"{s['edges']}" if s["edges"] else "—",
            )

        summary_table = Table(
            title="Overall Progress", title_style="bold green", expand=True
        )
        for col, style in [
            ("Label", None),
            ("Total", None),
            ("Finished", "bold green"),
            ("In-Progress", "cyan"),
            ("Failed/Incomplete", "bold red"),
        ]:
            summary_table.add_column(
                col, justify="right" if col != "Label" else "left", style=style
            )

        for label, v in s_snap.items():
            summary_table.add_row(
                label,
                str(v["total"]),
                str(v["finished"]),
                str(v["in_progress"]),
                str(v["failed"] + v["incomplete"]),
            )

        # Padding creates a 1-character visual gap between the two panels
        bottom_grid = Table.grid(expand=True, padding=(0, 1))
        bottom_grid.add_column(ratio=3)
        bottom_grid.add_column(ratio=2)
        bottom_grid.add_row(
            Panel(
                "\n".join(e_snap) if e_snap else "[dim]No events yet...[/]",
                title="Recent Events",
                border_style="blue",
            ),
            Panel(
                "\n".join(f_snap) if f_snap else "[dim]All trials healthy[/]",
                title="Failed Trials",
                border_style="red",
            ),
        )
        return Group(
            core_table,
            summary_table,
            bottom_grid,
        )


# ────────────────────────────  ENVIRONMENT  ────────────────────────────


class EnvironmentManager:
    """One-time synchronous setup run before any trial threads start: binary check,
    `smitebot doctor` preflight, required-file checks, Docker image builds for every
    (config, target) pair, and (if needed) the IR mutator build."""

    @staticmethod
    def validate(afl_dir: Path, smite_dirs: dict, console: Console):
        """Abort early if `smitebot` is missing or its own doctor checks fail."""
        if not shutil.which("smitebot"):
            sys.exit(
                "ERROR: 'smitebot' not found in PATH. Install via `cargo install --path smitebot`."
            )

        for label, smite_dir in smite_dirs.items():
            console.print(f"[bold cyan]Running smitebot doctor for '{label}'...[/]")
            res = subprocess.run(
                [
                    "smitebot",
                    "doctor",
                    "--aflpp-path",
                    str(afl_dir),
                    "--smite-dir",
                    str(smite_dir),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            try:
                data = json.loads(res.stdout)
                if not data.get("overall"):
                    for c in data.get("checks", []):
                        if not c.get("passed"):
                            console.print(
                                f"[red] - {c.get('name')}: {c.get('reason')}[/]"
                            )
                    sys.exit(1)
                console.print("[bold green]smitebot doctor checks passed![/]\n")
            except Exception:
                sys.exit(
                    f"[bold red]Doctor failed to parse output.[/]\n{res.stdout}\n{res.stderr}"
                )

    @staticmethod
    def validate_paths(afl_dir: Path, smite_dirs: dict, console: Console):
        """Check the required execution files so a missing one fails fast instead of mid-campaign."""
        required = {
            "afl-fuzz binary": afl_dir / "afl-fuzz",
        }
        for label, smite_dir in smite_dirs.items():
            required[f"setup-nyx.sh ({label})"] = smite_dir / "scripts" / "setup-nyx.sh"

        missing = {name: p for name, p in required.items() if not p.exists()}
        if missing:
            console.print("[bold red]Missing required file(s):[/]")
            for name, p in missing.items():
                console.print(f"  - {name}: {p}")
            sys.exit(1)

    @staticmethod
    def build_docker_images(
        targets: list[str], scenario: str, smite_dirs: dict, console: Console
    ):
        """Build every distinct (label, target) Docker image up front."""
        console.print("[bold cyan]Pre-building isolated Docker images…[/]")
        for label, smite_dir in smite_dirs.items():
            for tgt in targets:
                default_tag = f"smite-{tgt}-{scenario}"
                isolated_tag = f"smite-{label}-{tgt}-{scenario}"

                console.print(f"\n[bold]Building {isolated_tag} from {smite_dir}[/]")
                if (
                    subprocess.run(
                        [
                            "smitebot",
                            "build",
                            "--target",
                            tgt,
                            "--scenario",
                            scenario,
                            "--smite-dir",
                            str(smite_dir),
                        ]
                    ).returncode
                    != 0
                ):
                    sys.exit(f"[bold red]BUILD FAILED for {isolated_tag}[/]")

                # Tag it so the next worktree's build doesn't overwrite it
                subprocess.run(["docker", "tag", default_tag, isolated_tag], check=True)

    @staticmethod
    def build_ir_mutator(smite_dirs: dict, console: Console):
        """Builds the smite-ir-mutator shared library in release mode once, up front,
        if the scenario needs it (similar to how `smitebot start` does it)."""
        for label, smite_dir in smite_dirs.items():
            console.print(
                f"[bold cyan]Building smite-ir-mutator (release) for '{label}'...[/]"
            )
            if (
                subprocess.run(
                    ["cargo", "build", "--release", "-p", "smite-ir-mutator"],
                    cwd=smite_dir,
                ).returncode
                != 0
            ):
                sys.exit(
                    f"[bold red]cargo build for smite-ir-mutator FAILED in {smite_dir}[/]"
                )


# ────────────────────────────  TRIAL RUNNER  ────────────────────────────


class TrialRunner:
    """Owns the full lifecycle of a single fuzzing trial: filesystem/sharedir prep,
    direct afl-fuzz process spawn, boot detection, live telemetry polling, and
    teardown."""

    COMPLETION_GRACE_PERIOD_SEC = 120
    """A trial that ran for at least (timeout - this) is counted as COMPLETE rather
    than INCOMPLETE. Accounts for the gap between the configured `-V` AFL++ timeout
    and the wall-clock time afl-fuzz actually takes to notice, flush stats, and exit."""

    STARTUP_POLL_INTERVAL = 5
    """Seconds between boot-status polls in wait_for_boot()."""

    BOOT_TIMEOUT_SEC = 600
    """Max seconds to wait for `fuzzer_stats` to appear before aborting the trial as
    a boot failure. fuzzer_stats is only written once AFL++ finishes calibrating
    every seed, which under Nyx can take minutes, so this is deliberately generous —
    it only bounds a runner that stays alive but never finishes booting; an outright
    process death is detected immediately via poll(), well before this ceiling."""

    def __init__(self, config: TrialConfig, state: CampaignState):
        self.cfg = config
        self.state = state

        self.process = None
        self.fuzzer_pid = None
        self.start_time = 0.0
        self._started = False
        self.aborted = False

    def run(self):
        """Executes the trial lifecycle with strict exception handling."""
        try:
            self.prepare_fs()
            if self.spawn() and self.wait_for_boot():
                self.monitor()
        except Exception as e:
            self._abort(f"RUNTIME EXCEPTION: {e}", "failed")
        finally:
            self.cleanup()

    def prepare_fs(self):
        """Reset this trial's output directory and ensure its Nyx sharedir exists."""
        shutil.rmtree(self.cfg.trial_dir, ignore_errors=True)
        self.cfg.afl_out_dir.mkdir(parents=True)
        self.ensure_sharedir()

    def ensure_sharedir(self):
        """Run `setup-nyx.sh` to create this trial's fresh Nyx sharedir."""
        self.state.update_worker(
            self.cfg.core, status="Setting up Nyx sharedir...", color="cyan"
        )
        script = self.cfg.smite_dir / "scripts" / "setup-nyx.sh"
        with self.state.sharedir_lock:
            result = subprocess.run(
                [
                    str(script),
                    str(self.cfg.sharedir),
                    self.cfg.image_tag,
                    str(self.cfg.afl_dir),
                ],
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            raise RuntimeError(
                f"setup-nyx.sh failed (code {result.returncode}): "
                f"{(result.stderr or result.stdout).strip()[:300]}"
            )

    def spawn(self) -> bool:
        """Launch `afl-fuzz` directly, pinned to this trial's core via taskset."""
        self.start_time = time.time()
        self.state.update_worker(
            self.cfg.core,
            task=self.cfg.task_name,
            status="Spawning AFL++...",
            color="yellow",
            start_time=self.start_time,
            is_active=True,
            execs_sec=0.0,
            edges=0,
        )

        self.state.update_summary(self.cfg.label, "in_progress", 1)
        self._started = True

        cmd = self.cfg.build_afl_cmd()
        env = self.cfg.build_afl_env()

        self.log_file = open(self.cfg.log_path, "w")
        self.process = subprocess.Popen(
            cmd,
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # makes pid == pgid, so killpg() works in cleanup
        )
        # We track the direct child PID for exact lifecycle management.
        self.fuzzer_pid = self.process.pid
        return True

    def wait_for_boot(self) -> bool:
        """Poll for fuzzer_stats (boot complete) or process death (boot failure)."""
        self.state.update_worker(self.cfg.core, status="Booting VM...", color="cyan")

        for _ in range(self.BOOT_TIMEOUT_SEC // self.STARTUP_POLL_INTERVAL):
            if self.state.shutdown.is_set():
                return False

            ret = self.process.poll()
            if ret is not None:
                self._abort(
                    f"AFL++ EXITED DURING BOOT (code {ret}) — see {self.cfg.log_path.name}"
                )
                return False

            if self._log_has_abort():
                self._abort(f"AFL++ PROGRAM ABORT — see {self.cfg.log_path.name}")
                return False

            if self.cfg.stats_file.exists():
                return True

            time.sleep(self.STARTUP_POLL_INTERVAL)

        self._abort("BOOT TIMEOUT (Check log)")
        return False

    def _log_has_abort(self) -> bool:
        """Fast-path failure detection: AFL++ prints PROGRAM ABORT well before
        crashing out, so we don't have to wait for poll() to notice the exit."""
        try:
            return "PROGRAM ABORT" in self.cfg.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return False

    def _read_stats(self) -> dict:
        return {
            k.strip(): v.strip()
            for k, v in (
                l.split(":", 1)
                for l in self.cfg.stats_file.read_text().splitlines()
                if ":" in l
            )
        }

    def monitor(self):
        """Poll fuzzer_stats every 2s and push execs/sec + edges to the dashboard,
        until afl-fuzz exits (naturally via its own -V timeout, shutdown, or some error)."""
        self.state.register_pid(self.fuzzer_pid)
        self.state.update_worker(self.cfg.core, status="Fuzzing...", color="bold green")

        last_edges = 0
        while self.process.poll() is None and not self.state.shutdown.is_set():
            try:
                stats = self._read_stats()
                execs = float(stats.get("execs_per_sec", 0.0))
                edges = int(stats.get("edges_found", 0))

                last_edges = max(edges, last_edges)
                self.state.update_worker(
                    self.cfg.core, execs_sec=execs, edges=last_edges
                )
            except (FileNotFoundError, ValueError, KeyError):
                # Expected transiently: stats file mid-write or not yet flushed.
                pass
            except Exception as e:
                self.state.log(self.cfg.task_name, f"Monitor error: {e}", "red")

            time.sleep(2)

        # Catch mid-flight crashes. afl-fuzz exits with 0 on timeout,
        # but if QEMU aborts, it returns a non-zero error code.
        ret = self.process.poll()
        if ret is not None and ret != 0 and not self.state.shutdown.is_set():
            self._abort(
                f"AFL++ CRASHED MID-TRIAL (code {ret}) — see {self.cfg.log_path.name}"
            )

    def cleanup(self):
        """Kill any leftover fuzzer process, reclaim disk, and record final trial status."""
        if self.fuzzer_pid:
            self.state.unregister_pid(self.fuzzer_pid)
            try:
                os.killpg(self.fuzzer_pid, signal.SIGKILL)
            except OSError:
                pass

        if self.process and self.process.poll() is None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if hasattr(self, "log_file"):
            self.log_file.close()

        shutil.rmtree(self.cfg.afl_out_dir / "workdir", ignore_errors=True)
        shutil.rmtree(self.cfg.sharedir, ignore_errors=True)

        if self.aborted:
            return

        # See COMPLETION_GRACE_PERIOD_SEC docstring for the rationale behind the
        # `timeout - grace_period` threshold.
        is_complete = (time.time() - self.start_time) >= (
            self.cfg.timeout - self.COMPLETION_GRACE_PERIOD_SEC
        ) and not self.state.shutdown.is_set()

        self.state.update_worker(
            self.cfg.core,
            status="Done",
            color="dim",
            is_active=False,
            execs_sec=0.0,
            edges=0,
        )

        if self._started:
            self.state.update_summary(self.cfg.label, "in_progress", -1)
            self._started = False

        if is_complete:
            self.state.update_summary(self.cfg.label, "finished", 1)
            self.state.log(self.cfg.task_name, "COMPLETE", "bold green")
        else:
            self.state.update_summary(self.cfg.label, "incomplete", 1)
            self.state.log(self.cfg.task_name, "INCOMPLETE", "yellow")

        self.state.finish_trial()

    def _abort(self, msg: str, summary_field: str = "failed"):
        """Mark this trial as aborted, finalize its summary counters, and log why."""
        self.aborted = True
        self.state.update_worker(
            self.cfg.core, status="Failed", color="bold red", is_active=False
        )

        if self._started:
            self.state.update_summary(self.cfg.label, "in_progress", -1)
            self._started = False

        self.state.record_failure(self.cfg.task_name)
        self.state.update_summary(self.cfg.label, summary_field, 1)
        self.state.log(self.cfg.task_name, msg, "bold red")


# ────────────────────────────  ENTRY POINT  ────────────────────────────


def worker_thread(core: int, work: Queue, args, state: CampaignState, smite_dirs: dict):
    """Per-core worker loop: pull trials off the shared queue until it's empty or
    shutdown is requested, running each one to completion via TrialRunner.run().
    """
    while not state.shutdown.is_set():
        try:
            label, target, trial_num = work.get_nowait()
        except Empty:
            state.update_worker(
                core,
                task="Idle",
                status="-",
                color="dim",
                is_active=False,
                execs_sec=0.0,
                edges=0,
            )
            return

        config = TrialConfig(
            core=core,
            label=label,
            target=target,
            trial_num=trial_num,
            scenario=args.scenario,
            out_dir=args.out_dir,
            smite_dir=smite_dirs[label],
            afl_dir=args.afl_dir,
            timeout=args.timeout,
            seed_dir=args.seed_dir,
        )

        runner = TrialRunner(config, state)
        runner.run()
        work.task_done()


def ensure_seed_dir(args, console: Console):
    """Resolve args.seed_dir to a real, non-empty directory, creating a minimal
    one-byte corpus if the user didn't pass --seed-dir.

    This setup is performed once, up front, shared across every trial in this run
    (similar to how `smitebot start` handles seed provisioning)."""
    if args.seed_dir:
        if not args.seed_dir.is_dir():
            sys.exit(f"ERROR: Seed directory '{args.seed_dir}' does not exist.")
        return

    default_seeds = args.out_dir / ".default-seeds"
    default_seeds.mkdir(parents=True, exist_ok=True)
    if not any(default_seeds.iterdir()):
        (default_seeds / "seed0").write_bytes(b"\x00")
    args.seed_dir = default_seeds
    console.print(
        f"[dim]No --seed-dir given; using minimal generated corpus at {default_seeds}[/]"
    )


def parse_args():
    """Parse CLI args and resolve all filesystem paths to absolute up front."""
    p = argparse.ArgumentParser(
        description="Smite Fuzzing Coverage Campaign Orchestrator"
    )
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--configs", required=True, help="'label:smite_dir,label:smite_dir'")
    p.add_argument("--scenario", required=True, help="e.g. ir")
    p.add_argument("--targets", required=True, help="e.g. cln,lnd")
    p.add_argument("--cores", required=True, help="e.g. 0,1,2,3")
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument("--trials", type=int, default=30)
    p.add_argument(
        "--trial-ids",
        help="Comma-separated trial numbers to run, e.g. '1,5,15'. Overrides --trials.",
    )
    p.add_argument("--timeout", type=int, default=86400)
    p.add_argument("--seed-dir", type=Path)

    args = p.parse_args()

    args.out_dir = args.out_dir.resolve()
    args.afl_dir = args.afl_dir.resolve()
    if args.seed_dir:
        args.seed_dir = args.seed_dir.resolve()

    return args


def main():
    """Campaign entry point: validate environment, build images (and IR mutator if
    needed), queue all trials, spin up one worker thread per core, and render the
    live dashboard until done."""
    args = parse_args()
    console = Console()

    ensure_seed_dir(args, console)

    labels, smite_dirs = [], {}
    try:
        for item in args.configs.split(","):
            l, d = item.split(":")
            l = l.strip()
            labels.append(l)
            smite_dirs[l] = Path(d.strip()).expanduser().resolve()
    except ValueError:
        sys.exit("ERROR: --configs must use 'label:smite_dir' format")

    EnvironmentManager.validate(args.afl_dir, smite_dirs, console)
    EnvironmentManager.validate_paths(args.afl_dir, smite_dirs, console)

    targets = [t.strip() for t in args.targets.split(",")]
    cores = [int(c) for c in args.cores.split(",")]

    EnvironmentManager.build_docker_images(targets, args.scenario, smite_dirs, console)

    if args.scenario.startswith("ir"):
        EnvironmentManager.build_ir_mutator(smite_dirs, console)

    state = CampaignState(labels, cores)

    def _handle_sigint(sig, frame):
        """First Ctrl+C: stop queueing new trials and kill active fuzzers gracefully.
        Second Ctrl+C: force-quit immediately via os._exit, skipping further cleanup.
        """
        if state.shutdown.is_set():
            console.print("\n[bold red]Force-quitting immediately![/]")
            os._exit(1)
        state.shutdown.set()
        console.print(
            "\n[bold yellow]Interrupt received — gracefully killing fuzzers... (Press Ctrl+C again to force quit)[/]"
        )
        with state.pid_lock:
            for pid in state.active_pids:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass

    signal.signal(signal.SIGINT, _handle_sigint)

    if args.trial_ids:
        try:
            trial_range = [int(x.strip()) for x in args.trial_ids.split(",")]
        except ValueError:
            sys.exit("ERROR: --trial-ids must be a comma-separated list of integers.")
        display_trials = len(trial_range)
    else:
        trial_range = list(range(1, args.trials + 1))
        display_trials = args.trials

    # Enqueue every (label, target, trial_num) combination up front; workers pull
    # from this shared queue rather than being statically assigned ranges.
    work = Queue()
    for label in labels:
        for tgt in targets:
            for i in trial_range:
                work.put((label, tgt, i))
                state.summary[label]["total"] += 1
    state.total = sum(s["total"] for s in state.summary.values())

    print_campaign_summary(
        console=console,
        targets=targets,
        labels=labels,
        trials=display_trials,
        cores=cores,
        state=state,
        timeout=args.timeout,
    )

    threads = [
        threading.Thread(
            target=worker_thread, args=(c, work, args, state, smite_dirs), daemon=True
        )
        for c in cores
    ]

    with Live(
        DashboardRenderer.render(state), refresh_per_second=4, console=console
    ) as live:
        for t in threads:
            t.start()
        while any(t.is_alive() for t in threads):
            live.update(DashboardRenderer.render(state))
            time.sleep(0.25)
        for t in threads:
            t.join()

        live.update(DashboardRenderer.render(state))

    if state.shutdown.is_set():
        console.print("[bold yellow]Stopped early due to interrupt.[/]")
    else:
        console.print(
            "\n[bold green]=== All trials complete! Ready for analysis. ===[/]"
        )
        if len(labels) == 2:
            console.print(
                f"Run: [cyan]python scripts/smite-evaluation.py {args.out_dir} {labels[0]} {labels[1]}[/]"
            )


if __name__ == "__main__":
    main()
