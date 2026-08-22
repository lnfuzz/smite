# smitebot

`smitebot` is the Smite automation CLI. It orchestrates fuzzing campaigns against Lightning Network implementations using AFL++ and Nyx, reducing multi-step manual workflows to single commands.

## Install

```bash
cargo install --path smitebot
```

## Configuration

Campaign settings are stored in a TOML file. See [`sample-campaign.toml`](sample-campaign.toml) for a complete example.

| Field          | Required | Description                                                                               |
| -------------- | -------- | ----------------------------------------------------------------------------------------- |
| `target`       | yes      | Lightning implementation to fuzz (`lnd`, `cln`, `ldk`, or `eclair`).                      |
| `scenario`     | yes      | Scenario binary selected by the workload Dockerfile.                                      |
| `aflpp_path`   | yes      | Path to the AFL++ source tree.                                                            |
| `smite_dir`    | yes      | Path to the smite repository root.                                                        |
| `runners`      | yes      | Number of parallel AFL++ instances to launch (must be at least 1).                        |
| `seed_dir`     | no       | Directory containing seed inputs; omit to start from an empty corpus.                     |
| `output_dir`   | yes      | AFL++ output directory for findings and stats.                                            |
| `sharedir`     | yes      | Nyx shared directory path; created automatically by `smitebot start`.                     |
| `image`        | no       | Docker image tag override; defaults to `smite-<target>-<scenario>`.                       |
| `tmux_session` | no       | Custom tmux session name; defaults to the campaign ID. Must not contain `:`, `.`, or `#`. |
| `afl_env`      | no       | Extra environment variables passed to AFL++ instances.                                    |
| `afl_flags`    | no       | Extra CLI flags appended to `afl-fuzz`.                                                   |

## Commands

### smitebot start

Launches a fuzzing campaign. Builds the Docker image, sets up the Nyx sharedir, spawns parallel AFL++ instances inside a tmux session (one window per runner), and attaches to the session.

```bash
smitebot start campaign.toml
```

Each runner gets a deterministic strategy distribution. The primary runner (0)
runs AFL++'s default schedule with no modifiers; secondaries carry the schedule
and mutation modifiers below. The power schedule is round-robin by index; the
remaining modifiers are spread across secondaries by a fixed hash of the runner
index, so a given runner always draws the same flags:
- Power schedule (`-p`, secondaries only): round-robin across `explore`, `fast`, `coe`, `lin`, `quad`, `exploit`, `rare`
- `-a binary`: ~70% of secondaries (wire messages are binary; hints AFL++ to use binary mutation strategies)
- `-P` (fixed mutation strategy): `explore` ~40% / `exploit` ~20% of secondaries
- `-L 0` (MOpt mode): ~10% of secondaries; skipped when a custom mutator is set (incompatible with MOpt)
- `-Z` (sequential queue selection): ~10% of secondaries
- `AFL_DISABLE_TRIM`: ~60% of secondary runners
- `AFL_FINAL_SYNC`: primary runner only
- `AFL_IMPORT_FIRST`: enabled when runner count < 16
- `AFL_TESTCACHE_SIZE`: auto-sized from available RAM

For IR scenarios (scenario names starting with `ir`), the required AFL++ custom mutator environment variables are injected automatically. User `afl_env` values override strategy defaults.

`start` begins fresh campaigns only. If `output_dir` already holds a prior run's `fuzzer_stats`, it exits with an error instead of resuming (resume is not yet supported).

After spawning, startup is verified by polling for `fuzzer_stats` files. Because AFL++ writes `fuzzer_stats` only after calibrating every seed (minutes under Nyx), a runner is reported as failed the moment its tmux window exits rather than after a fixed timeout; the poll otherwise waits up to a generous ceiling (10 min) for a runner that stays alive but never starts. On failure, the tmux session is preserved with `remain-on-exit` so error output can be inspected.

Campaign state is saved to `~/.smitebot/runs/<campaign-id>/state.json` for use by future `stop` and `status` commands.

### smitebot stop

Stops a running campaign: reaps every runner's process group — afl-fuzz and its Nyx QEMU child, which shares the group — tears down the tmux session, and records the stop time in `state.json`.

```bash
smitebot stop <campaign-id>
```

`<campaign-id>` is the directory name under `~/.smitebot/runs` (printed by `smitebot start`). 

### smitebot status

Reports the status of a campaign. Detects whether the campaign is still running (its tmux session is alive) and adapts:

```bash
smitebot status <campaign-id>
smitebot status <campaign-id> --summary
```

- `--summary`: Print a one-shot text summary to the terminal instead of attaching to the live dashboard.
- `<campaign-id>` is the directory name under `~/.smitebot/runs` (printed by `smitebot start`).

### smitebot bench-exec

Benchmarks Nyx execution speed by running a single input through the target's VM many times. Each execution is a snapshot restore plus one target run, so the results isolate VM/snapshot and target speed from AFL++'s mutation and scheduling overhead.

```bash
smitebot bench-exec campaign.toml
smitebot bench-exec campaign.toml --input testcase.bin --iterations 5000
```

- `--input`: Input file to execute repeatedly. Defaults to a single `0x00` byte. The default is handy for quickly measuring performance gains that come from the target itself rather than a specific test case: every exec still does the live-target ping-pong the executor uses to confirm the VM is up, so it exercises that path. It's a fast way to check improvements like JVM warmup/optimization.
- `-n`, `--iterations`: Number of timed executions per run (default `1000`).
- `-r`, `--repeat`: Number of full boot+measure runs to average over (default `1`). Each run boots a fresh VM, so repeats capture boot- and snapshot-level variance a single run cannot.
- `--worker-id`: Nyx worker id, which namespaces the VM's workdir files (default `0`).
- `--cpu`: CPU to pin the benchmark and its VM to (defaults to `--worker-id`). libnyx does no CPU binding of its own, so `bench-exec` sets its own affinity before booting and QEMU inherits it, the same way `afl-fuzz` does. On a hybrid CPU, pin to a core of the type you mean to measure: a P-core and an E-core give materially different numbers.
- `--max-input-size`: Input buffer size in bytes for the VM, which must be a multiple of 4096 (QEMU-Nyx asserts the payload buffer is page-aligned). Defaults to `1048576`, AFL++'s `MAX_FILE` and therefore the buffer a real campaign runs with.
- `-t`, `--timeout`: Per-execution timeout in seconds; an exec that runs longer is counted as timed out (default `2`).
- `--no-build`: Skip building the image and setting up the sharedir; reuse an existing one.

Like `start`, `bench-exec` builds the Docker image and sets up the Nyx sharedir before running, so it works from a clean checkout. Pass `--no-build` to skip that and reuse an already-prepared sharedir (`sharedir/config.ron`) from a prior `start`, `bench-exec`, or `scripts/setup-nyx.sh`. Either way it needs `libnyx.so` under `aflpp_path`, which it loads at runtime the same way `afl-fuzz` does.

Booting the VM is what pays for target init and root snapshot creation: libnyx does not return from boot until the guest has reached its ready-to-fuzz state, so that cost is timed on its own. Every execution after that is a snapshot restore plus one target run; they are all timed together and reported as steady-state throughput:

```
Smite Nyx benchmark
  target:      ldk/ir
  sharedir:    /tmp/smite-nyx
  input size:  406 bytes
  input buffer:1048576 bytes
  iterations:  100
  repeats:     1

  boot + snapshot creation: 4.056 s
  steady-state (snapshot restore + target run):
    execs/sec: 8.8
    exec time: 11.324 s
    latency:   min 106.16 ms  mean 113.24 ms  median 113.84 ms  p99 116.02 ms  max 116.06 ms
    input execution: mean 109.35 ms  median 110.31 ms   (guest runtime)
    nyx overhead:    mean 3.89 ms  median 4.00 ms   (restore + reset + ipc; 4045 dirty pages/exec)
    failed iterations: 0 / 100
    coverage determinism: 84.8% stable (2808 / 18456 edges fluctuated)
```

Each per-exec latency is split into two parts read from libnyx's auxiliary buffer:

- **input execution** is the guest runtime the target actually spent processing the input, measured inside the VM. This is the "true" cost of the input; use it to tell whether a change made the target's own work faster.
- **nyx overhead** is the wall time minus that guest runtime: snapshot restore/reset plus hypercall round-trips. `dirty pages/exec` is the number of pages restored each execution, the main driver of that overhead, so a change that dirties more memory (e.g. spawning a process per block) shows up as both higher overhead and more dirty pages.

`coverage determinism` reports how reproducible the target's edge coverage is across the identical executions. Each execution's AFL coverage bitmap is captured and its per-edge hit counts are bucketed with AFL's count classes; an edge whose bucketed count is not identical across all executions is counted as fluctuated, and the denominator is the edges hit at least once. High determinism (close to 100%) means the same input reliably reaches the same code; fluctuation points to nondeterminism (uninitialized memory, timing-dependent branches, ASLR, background threads) that adds noise to the fuzzer's coverage signal. Bucketing means benign loop-trip jitter is not counted.

With `--repeat` greater than 1 each run is reported separately, followed by an aggregate (mean, stddev, and range of execs/sec across runs; coverage determinism is pooled over all runs).

`failed iterations` counts executions that ended in a crash, timeout, or error rather than a clean run; a non-zero count means the input is not a clean steady-state case and the numbers are skewed.

### smitebot config

Validates a campaign configuration file, reports the resolved settings, and checks that referenced paths exist on disk.

```bash
smitebot config campaign.toml
smitebot config campaign.toml --json
```

- `--json`: Emit machine-readable JSON output. Both success and error paths produce valid JSON.

### smitebot build

Builds Smite workload Docker images. Accepts a campaign config file or standalone CLI flags. When both are provided, CLI flags override config values.

```bash
smitebot build --target lnd --scenario encrypted_bytes
smitebot build campaign.toml
smitebot build campaign.toml --target cln
smitebot build campaign.toml --coverage --no-cache
```

- `--target`: Target implementation to build. Required when no config file is provided.
- `--scenario`: Scenario binary for the workload Dockerfile. Required when no config file is provided.
- `--smite-dir`: Path to the smite repository root; defaults to `.` when no config file is provided.
- `--coverage`: Build a coverage-instrumented image.
- `--image`: Docker image tag; overrides the config value and the default naming convention.
- `--no-cache`: Perform a clean rebuild without using cached Docker layers.

Image tags follow the Smite convention: `smite-<target>-<scenario>` or `smite-<target>-<scenario>-coverage`.

### smitebot doctor

Validates host prerequisites before running Smite campaigns. Accepts a campaign config file or standalone CLI flags. When both are provided, CLI flags override config values.

```bash
smitebot doctor --aflpp-path ~/AFLplusplus
smitebot doctor campaign.toml
smitebot doctor campaign.toml --json
smitebot doctor campaign.toml --aflpp-path ~/other-aflpp
```

- `--aflpp-path`: Path to AFL++ source tree. Required when no config file is provided.
- `--smite-dir`: Path to the smite repository root; overrides the config value.
- `--json`: Emit machine-readable JSON output.

Checks performed:

- `x86_64` architecture
- CPU virtualization enabled (`vmx` or `svm`)
- `/dev/kvm` is present and openable
- Docker daemon is reachable (`docker version`)
- AFL++ built with Nyx support (`libnyx.so` under `--aflpp-path`)
- VMware backdoor is enabled
- AFL++ tools (`afl-fuzz`, `afl-cmin`, `afl-tmin`, `afl-whatsup`) are executable
- Required host tools (`bash`, `python`, `python3`, `tmux`)
- Required Smite scripts are present and executable
- Required workload Dockerfiles are present

JSON output example:

```json
{
  "checks": [
    { "name": "x86_64 architecture", "passed": true },
    { "name": "Docker daemon reachable", "passed": false, "reason": "docker version: exit status: 1" }
  ],
  "overall": false
}
```

### smitebot print-ir

Decodes a serialized IR program and prints it to standard output. IR programs are opaque postcard-encoded `Program`s, the same form the fuzzing loop serializes them in; point it at one to see what it actually does.

```bash
smitebot print-ir <path>
smitebot print-ir output/default/crashes/id:000000,sig:06,...
```

`<path>` is a path to a postcard-encoded IR program.

The program is printed using the IR's `Display` format, the same textual form the `smite-ir` mutator emits in its trim logs. An empty program prints `(empty program)`.

### smitebot corpus merge

Collects all queue files from one or more campaign runner directories, deduplicates by content, and writes unique files to an output directory. Accepts multiple campaign IDs to merge corpora across independent runs.

```bash
smitebot corpus merge <campaign-id> -o <output-dir>
smitebot corpus merge <campaign-id-1> <campaign-id-2> ... -o <output-dir>
```

- `<campaign-id>`: directory name(s) under `~/.smitebot/runs`
- `-o, --output <output-dir>`: output directory for the merged corpus (required)

### smitebot corpus minimize

Removes corpus inputs that do not contribute new coverage, using `afl-cmin` in Nyx mode (`-X`). Reads `sharedir` and `aflpp_path` from the campaign's `state.json`; no live campaign required.

```bash
smitebot corpus minimize <campaign-id>
smitebot corpus minimize <campaign-id> [-i <dir>]... [-o <output-dir>] [--aflpp-path <path>]
```

- `<campaign-id>`: directory name under `~/.smitebot/runs`
- `-i, --input <dir>`: One input directory to minimize. If multiple `-i` flags are present, all specified directories are merged before minimizing. If omitted, the campaign's runner queues are merged and minimized.
- `-o, --output <output-dir>`: output directory; defaults to `~/.smitebot/runs/<id>/corpus-min/`
- `--aflpp-path <path>`: AFL++ source tree, overriding the `aflpp_path` stored in `state.json` (useful when the checkout has moved)

### smitebot reproduce

Replays a single input against a campaign's target and streams the target's output to the terminal; `reproduce` interprets nothing — read the logs to see what happened. Resolves the image and target from the campaign's `state.json`; no live campaign required.

```bash
smitebot reproduce <campaign-id> -i <input>
```

- `<campaign-id>`: directory name under `~/.smitebot/runs`
- `-i, --input <input>`: input file to replay, e.g. a crash from a runner's `crashes/` directory

If the image's digest no longer matches the one recorded for the campaign (e.g. it was rebuilt under the same tag), a warning is logged. Reproduction under Nyx is not yet supported.
