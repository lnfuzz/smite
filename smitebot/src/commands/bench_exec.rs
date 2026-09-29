//! Single-input Nyx benchmark.
//!
//! Boots the target's Nyx VM and runs one fixed input through it a fixed number
//! of times, measuring steady-state throughput and per-execution latency.
//! Because each execution is a snapshot restore plus one target run, the numbers
//! isolate VM/snapshot and target speed from AFL++'s mutation and scheduling
//! overhead.
//!
//! Like `start`, `bench-exec` builds the Docker image and sets up the Nyx
//! sharedir before running. Pass `--no-build` to skip that and reuse an
//! already-prepared sharedir (e.g. from a prior `start`, `bench-exec`, or
//! `scripts/setup-nyx.sh`).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Args;

use crate::commands::build::{BuildInputs, run_build};
use crate::config::CampaignConfig;
use crate::latency_stats::{LatencyStats, avg_duration, mean_stddev};
use crate::libnyx::{Libnyx, NyxReturn, PAYLOAD_HEADER_SIZE};
use crate::utils::{afl_bin_dir, pin_to_cpu, setup_nyx};

/// Default number of timed executions when `--iterations` is not given.
const DEFAULT_ITERATIONS: u64 = 1000;

/// Upper bound on `--iterations`. The run preallocates and retains timing
/// samples per iteration, so an unbounded count would reserve gigabytes.
const MAX_ITERATIONS: u64 = 1_000_000;

/// Upper bound on `--repeat`, which likewise sizes a preallocation.
const MAX_REPEAT: u32 = 1_000;

/// Guest page size (x86-64 base page, `x86_64_PAGE_SIZE` in QEMU-Nyx) that the
/// input buffer must be a whole multiple of.
///
/// QEMU-Nyx maps the payload buffer into the guest one page at a time and
/// asserts `shared_payload_buffer_size % x86_64_PAGE_SIZE == 0`
/// (`nyx_mode/QEMU-Nyx/nyx/memory_access.c`), so any buffer size we pass must be
/// page-rounded or the VM aborts. AFL++ never trips this because its buffer is a
/// page-multiple 1 MiB.
const NYX_PAGE_SIZE: u32 = 4096;

/// Input buffer size the VM is booted with unless `--max-input-size` says
/// otherwise: AFL++'s `MAX_FILE`, which is what afl-fuzz hands to
/// `nyx_config_set_input_buffer_size`.
///
/// Matching AFL++ by default means the benchmark measures the buffer a real
/// campaign runs with. Page-aligned, so it satisfies the QEMU-Nyx assertion
/// above.
const DEFAULT_MAX_INPUT_SIZE: u32 = 1 << 20;

/// Default per-execution timeout in seconds. An input that runs longer is
/// reported as a failed (timed-out) iteration rather than hanging the run.
const BENCH_TIMEOUT_SECS: u8 = 2;

/// Command handler for `smitebot bench-exec`.
pub struct BenchExecCommand;

/// CLI arguments for `smitebot bench-exec`.
#[derive(Debug, Args)]
pub struct BenchExecArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
    /// Input file to execute repeatedly; defaults to a single 0x00 byte.
    #[arg(long, short)]
    input: Option<PathBuf>,
    /// Number of timed executions to run (at most 1000000, since every
    /// execution's timing samples are held until the run ends).
    #[arg(long, short = 'n', default_value_t = DEFAULT_ITERATIONS)]
    iterations: u64,
    /// Number of full boot+measure runs to repeat and average over (at most 1000).
    ///
    /// Each run boots a fresh VM, so repeats capture boot- and snapshot-level
    /// variance that a single run cannot. Results are reported per run plus an
    /// aggregate.
    #[arg(long, short = 'r', default_value_t = 1)]
    repeat: u32,
    /// Nyx worker id for the VM, which namespaces its workdir files so several
    /// VMs can share a workdir.
    #[arg(long, default_value_t = 0)]
    worker_id: u32,
    /// CPU to pin the benchmark and its VM to; defaults to `--worker-id`.
    ///
    /// Pinning keeps the scheduler from migrating the VM mid-run. On a hybrid
    /// CPU, pick a core of the type you mean to measure: a P-core and an E-core
    /// give materially different numbers.
    #[arg(long)]
    cpu: Option<usize>,
    /// Input buffer size in bytes for the Nyx VM; must be a multiple of 4096.
    ///
    /// Defaults to AFL++'s 1 MiB, the buffer a real campaign runs with.
    #[arg(long, default_value_t = DEFAULT_MAX_INPUT_SIZE)]
    max_input_size: u32,
    /// Per-execution timeout in seconds before an exec is counted as timed out.
    /// Must be at least 1; Nyx reads zero as "no timeout".
    #[arg(long = "timeout", short = 't', default_value_t = BENCH_TIMEOUT_SECS)]
    timeout_secs: u8,
    /// Skip building the image and setting up the sharedir; reuse an existing one.
    #[arg(long)]
    no_build: bool,
}

impl BenchExecCommand {
    /// Runs the benchmark and returns whether it completed successfully.
    pub fn execute(args: &BenchExecArgs) -> bool {
        let iterations = match validate_iterations(args.iterations) {
            Ok(n) => n,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };
        let repeat = match validate_repeat(args.repeat) {
            Ok(n) => n,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };
        // A zero timeout causes Nyx to silently turn off the timing the
        // benchmark exists to measure.
        if args.timeout_secs == 0 {
            log::error!("Nyx requires --timeout to be at least 1 second");
            return false;
        }

        let config = match CampaignConfig::load(&args.path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        let input = match load_input(args) {
            Ok(input) => input,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };
        let max_input_size = match validate_max_input_size(args.max_input_size, input.len()) {
            Ok(size) => size,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        let Some(libnyx_path) = locate_libnyx(&config) else {
            return false;
        };

        if !ensure_sharedir(&config, args.no_build) {
            return false;
        }

        let libnyx = match Libnyx::load(&libnyx_path) {
            Ok(lib) => lib,
            Err(e) => {
                log::error!("failed to load {}: {e}", libnyx_path.display());
                return false;
            }
        };

        // Pin before booting: libnyx spawns QEMU as a child, so the VM inherits
        // this affinity mask. Doing it here also pins the timing loop itself.
        let cpu = args.cpu.unwrap_or(args.worker_id as usize);
        if let Err(e) = pin_to_cpu(cpu) {
            log::error!("{e}");
            return false;
        }
        log::info!("pinned to CPU {cpu}");

        // Each repeat is a fresh VM boot so the aggregate captures boot- and
        // snapshot-level variance, which dominates run-to-run spread.
        let mut runs = Vec::with_capacity(repeat);
        for run_index in 0..repeat {
            if repeat > 1 {
                log::info!("benchmark run {}/{repeat}", run_index + 1);
            }
            match run_once(
                &libnyx,
                &config,
                &input,
                args,
                max_input_size,
                iterations,
                run_index,
            ) {
                Ok(result) => runs.push(result),
                Err(e) => {
                    log::error!("{e}");
                    return false;
                }
            }
        }

        let report = BenchReport {
            target: format!("{}/{}", config.target, config.scenario),
            sharedir: config.sharedir.clone(),
            input_len: input.len(),
            max_input_size,
            iterations,
            runs,
        };
        report.print();

        true
    }
}

/// Boots a fresh VM, times one benchmark run, and tears the VM down.
fn run_once(
    libnyx: &Libnyx,
    config: &CampaignConfig,
    input: &[u8],
    args: &BenchExecArgs,
    max_input_size: u32,
    iterations: usize,
    run_index: usize,
) -> Result<RunResult, String> {
    let workdir = BenchWorkdir::create(&config.output_dir, run_index)
        .map_err(|e| format!("failed to create benchmark workdir: {e}"))?;

    // libnyx does not return until the guest reaches the ready-to-fuzz state, so
    // this call is where VM boot, target init, and root snapshot creation are
    // paid for (`QemuProcess::new` in libnyx spins until `result.state == 3`).
    log::info!("booting Nyx VM from {}", config.sharedir.display());
    let boot_start = Instant::now();
    let mut vm = libnyx.boot(
        &config.sharedir,
        workdir.path(),
        max_input_size,
        args.worker_id,
        args.timeout_secs,
    )?;
    let boot_time = boot_start.elapsed();

    // The coverage bitmap lets us measure how deterministic the target's edge
    // coverage is across identical executions. Skip it if libnyx reports no map.
    let bitmap_size = vm.bitmap_size();
    let mut coverage = (bitmap_size > 0).then(|| CoverageTracker::new(bitmap_size));
    let mut bitmap_buf = vec![0u8; bitmap_size];

    log::info!("running {iterations} timed executions");
    let mut latencies = Vec::with_capacity(iterations);
    let mut target_runtimes = Vec::with_capacity(iterations);
    let mut overheads = Vec::with_capacity(iterations);
    let mut failed_iterations = 0u64;
    let mut crash_reports: HashMap<String, u64> = HashMap::new();
    let mut dirty_pages_total = 0u64;
    // Throughput is the sum of the timed exec latencies, not the loop's wall
    // clock.
    let mut total = Duration::ZERO;
    for _ in 0..iterations {
        let exec_start = Instant::now();
        let stats = vm.exec_with_stats(input);
        let latency = exec_start.elapsed();
        total += latency;

        latencies.push(latency);
        target_runtimes.push(stats.target_runtime);
        // Overhead is the wall time not spent running the target: snapshot
        // restore/reset plus hypercall round-trips. Saturating guards the rare
        // case where the guest-measured runtime rounds above the host latency.
        overheads.push(latency.saturating_sub(stats.target_runtime));
        dirty_pages_total += u64::from(stats.dirty_pages);
        if !stats.result.is_normal() {
            failed_iterations += 1;
            // The crash buffer is written for these outcomes and never cleared,
            // so we only check the buffer when it changes.
            let report = match stats.result {
                NyxReturn::Crash | NyxReturn::Abort | NyxReturn::InvalidWriteToPayload => {
                    vm.crash_report()
                }
                _ => None,
            };
            let report = report.unwrap_or_else(|| format!("{:?} (no crash report)", stats.result));
            *crash_reports.entry(report).or_insert(0) += 1;
        }

        if let Some(tracker) = coverage.as_mut() {
            vm.copy_bitmap_into(&mut bitmap_buf);
            tracker.record(&bitmap_buf);
        }
    }

    // `vm` (QEMU shutdown) then `workdir` (rm -rf) drop in reverse order here.
    Ok(RunResult {
        boot_time,
        total,
        failed_iterations,
        mean_dirty_pages: mean_u64(dirty_pages_total, iterations),
        stats: LatencyStats::summarize(&mut latencies),
        target: LatencyStats::summarize(&mut target_runtimes),
        overhead: LatencyStats::summarize(&mut overheads),
        coverage: coverage.map(|c| c.summary()),
        crash_reports,
    })
}

/// Tracks per-edge coverage stability across the executions of one run.
///
/// AFL++'s bitmap holds one byte per edge, a raw hit count. The same input on a
/// deterministic target should light the same edges with the same *bucketed*
/// count every execution; an edge whose bucketed count varies across executions
/// is unstable (nondeterminism from uninitialized memory, timing-dependent
/// branches, ASLR, background threads, etc.). Bucketing with AFL++'s live count
/// classes means benign within-bucket jitter (e.g. 100 vs 101 iterations, both
/// in `[64..127]`) is not flagged, matching what actually perturbs AFL's
/// coverage.
struct CoverageTracker {
    /// Bucketed hit count from the first recorded execution, per edge.
    reference: Vec<u8>,
    /// Whether each edge was hit (nonzero) in any recorded execution.
    hit: Vec<bool>,
    /// Whether each edge's bucketed count ever differed from `reference`.
    fluctuated: Vec<bool>,
    /// Number of executions recorded so far.
    samples: u64,
}

impl CoverageTracker {
    fn new(bitmap_size: usize) -> Self {
        Self {
            reference: vec![0; bitmap_size],
            hit: vec![false; bitmap_size],
            fluctuated: vec![false; bitmap_size],
            samples: 0,
        }
    }

    /// Folds one execution's raw bitmap into the running tally.
    fn record(&mut self, bitmap: &[u8]) {
        for (i, &raw) in bitmap.iter().enumerate() {
            let bucket = classify_count(raw);
            if bucket != 0 {
                self.hit[i] = true;
            }
            if self.samples == 0 {
                self.reference[i] = bucket;
            } else if bucket != self.reference[i] {
                self.fluctuated[i] = true;
            }
        }
        self.samples += 1;
    }

    /// Collapses the tally into executed- and fluctuated-edge counts.
    fn summary(&self) -> CoverageSummary {
        let executed_edges = self.hit.iter().filter(|&&h| h).count() as u64;
        let fluctuated_edges = self.fluctuated.iter().filter(|&&f| f).count() as u64;
        CoverageSummary {
            executed_edges,
            fluctuated_edges,
        }
    }
}

/// AFL's count-class bucketing: raw hit counts collapse to fixed buckets so that
/// small variations within a bucket are treated as identical coverage.
///
/// Returns the bucket's index rather than AFL's bucket value. Only equality
/// between two executions matters here, so the index is equivalent and keeps the
/// ranges and their labels lined up.
fn classify_count(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2..=3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=63 => 6,
        64..=127 => 7,
        128..=255 => 8,
    }
}

/// Executed- and fluctuated-edge counts for one run's coverage stability.
#[derive(Clone, Copy)]
struct CoverageSummary {
    /// Edges hit (nonzero) in at least one execution.
    executed_edges: u64,
    /// Executed edges whose bucketed count was not identical across executions.
    fluctuated_edges: u64,
}

impl CoverageSummary {
    /// Percentage of executed edges that were stable across all executions.
    #[allow(clippy::cast_precision_loss)] // display figure; edge counts are small
    fn stable_pct(&self) -> f64 {
        if self.executed_edges == 0 {
            100.0
        } else {
            let stable = self.executed_edges - self.fluctuated_edges;
            stable as f64 / self.executed_edges as f64 * 100.0
        }
    }
}

/// Mean of a summed total over `count` samples, as a float (0.0 if no samples).
#[allow(clippy::cast_precision_loss)] // display figure; exact precision unneeded
fn mean_u64(total: u64, count: usize) -> f64 {
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

/// Validates `--iterations` and returns it as a `usize`, the length the run's
/// sample vectors are allocated from.
fn validate_iterations(iterations: u64) -> Result<usize, String> {
    if iterations == 0 {
        return Err("--iterations must be at least 1".to_string());
    }
    if iterations > MAX_ITERATIONS {
        return Err(format!(
            "--iterations must be at most {MAX_ITERATIONS}, got {iterations}"
        ));
    }
    usize::try_from(iterations)
        .map_err(|_| format!("--iterations is {iterations}, more than this platform can address"))
}

/// Validates `--repeat` and returns it as the capacity for the results vector.
fn validate_repeat(repeat: u32) -> Result<usize, String> {
    if repeat == 0 {
        return Err("--repeat must be at least 1".to_string());
    }
    if repeat > MAX_REPEAT {
        return Err(format!(
            "--repeat must be at most {MAX_REPEAT}, got {repeat}"
        ));
    }
    usize::try_from(repeat)
        .map_err(|_| format!("--repeat is {repeat}, more than this platform can address"))
}

/// Validates `--max-input-size` against the input it has to carry.
///
/// The size reaches QEMU-Nyx verbatim, so it is rejected rather than adjusted:
/// silently resizing the buffer would change the very thing the benchmark
/// measures.
fn validate_max_input_size(size: u32, input_len: usize) -> Result<u32, String> {
    if size == 0 || !size.is_multiple_of(NYX_PAGE_SIZE) {
        return Err(format!(
            "--max-input-size must be a nonzero multiple of {NYX_PAGE_SIZE} (QEMU-Nyx asserts \
             the payload buffer is page-aligned), got {size}"
        ));
    }
    // Saturating: the sum only has to be compared against a `u32`, so clamping an
    // absurd length at `u64::MAX` still rejects it, where adding would overflow.
    if (input_len as u64).saturating_add(u64::from(PAYLOAD_HEADER_SIZE)) > u64::from(size) {
        return Err(format!(
            "input is {input_len} bytes and its {PAYLOAD_HEADER_SIZE}-byte length prefix shares \
             the buffer, but --max-input-size is {size}; raise it (the guest allocates the whole \
             buffer every execution, so it must fit the VM's RAM)"
        ));
    }
    Ok(size)
}

/// Loads the input to benchmark, defaulting to a single zero byte.
fn load_input(args: &BenchExecArgs) -> Result<Vec<u8>, String> {
    match &args.input {
        Some(path) => {
            fs::read(path).map_err(|e| format!("failed to read input {}: {e}", path.display()))
        }
        None => Ok(vec![0u8]),
    }
}

/// Validates `aflpp_path` and locates `libnyx.so`, returning its path.
///
/// AFL++'s Nyx build is required both to prepare the sharedir (setup-nyx.sh)
/// and to drive the VM at runtime, so it is checked before either.
fn locate_libnyx(config: &CampaignConfig) -> Option<PathBuf> {
    if !config.aflpp_path.exists() {
        log::error!("aflpp_path does not exist: {}", config.aflpp_path.display());
        return None;
    }

    let libnyx_path = afl_bin_dir(&config.aflpp_path).join("libnyx.so");
    if !libnyx_path.exists() {
        log::error!(
            "{} not found; build AFL++ with Nyx support (see nyx_mode/README.md)",
            libnyx_path.display()
        );
        return None;
    }

    Some(libnyx_path)
}

/// Builds the image and sets up the sharedir, or (when `no_build`) verifies an
/// existing sharedir is present.
///
/// libnyx writes `config.ron` into the sharedir during setup-nyx.sh; its
/// absence means the sharedir was never prepared.
fn ensure_sharedir(config: &CampaignConfig, no_build: bool) -> bool {
    if no_build {
        let config_ron = config.sharedir.join("config.ron");
        if !config_ron.exists() {
            log::error!(
                "Nyx sharedir is not set up ({} missing); drop --no-build, or run \
                 `smitebot start` / scripts/setup-nyx.sh first",
                config_ron.display()
            );
            return false;
        }
        return true;
    }

    let image = config.image_tag();
    log::info!("building Docker image {image}");
    if !run_build(&BuildInputs::from_config(config, &image)) {
        return false;
    }

    log::info!("setting up Nyx sharedir at {}", config.sharedir.display());
    setup_nyx(config, &image)
}

/// A dedicated scratch directory for libnyx, removed on drop.
///
/// libnyx wipes its workdir on startup, so it must not be shared with campaign
/// output. A unique per-process directory keeps concurrent benchmarks isolated.
struct BenchWorkdir {
    path: PathBuf,
}

impl BenchWorkdir {
    fn create(output_dir: &Path, run_index: usize) -> std::io::Result<Self> {
        let path = output_dir.join(format!(".bench-{}-{run_index}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BenchWorkdir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.path) {
            log::debug!(
                "failed to remove benchmark workdir {}: {e}",
                self.path.display()
            );
        }
    }
}

/// Timing results from a single boot+measure run.
struct RunResult {
    /// Wall time of `libnyx.boot`: VM boot, target init, and snapshot creation.
    boot_time: Duration,
    /// Summed exec latency over the run (throughput denominator); excludes
    /// harness bookkeeping so it equals `iterations * mean latency`.
    total: Duration,
    failed_iterations: u64,
    /// Mean pages restored per execution (the Nyx overhead's main driver).
    mean_dirty_pages: f64,
    /// Per-exec wall time (target run + Nyx overhead).
    stats: LatencyStats,
    /// Per-exec guest runtime of the target alone (the "true" input execution).
    target: LatencyStats,
    /// Per-exec Nyx overhead (wall time minus target runtime).
    overhead: LatencyStats,
    /// Edge-coverage stability across the run, if a bitmap was available.
    coverage: Option<CoverageSummary>,
    /// Crash reports encountered and counts of occurrences.
    crash_reports: HashMap<String, u64>,
}

impl RunResult {
    /// Steady-state throughput for this run.
    // Execs/sec is a display figure; f64 precision loss on the exec count is
    // immaterial at any realistic iteration count.
    #[allow(clippy::cast_precision_loss)]
    fn execs_per_sec(&self, iterations: usize) -> f64 {
        iterations as f64 / self.total.as_secs_f64()
    }
}

/// A completed benchmark (one or more runs), ready to print.
struct BenchReport {
    target: String,
    sharedir: PathBuf,
    input_len: usize,
    max_input_size: u32,
    /// Timed executions per run, validated to fit a `usize` before the runs start.
    iterations: usize,
    runs: Vec<RunResult>,
}

impl BenchReport {
    fn print(&self) {
        println!("Smite Nyx benchmark");
        println!("  target:      {}", self.target);
        println!("  sharedir:    {}", self.sharedir.display());
        println!("  input size:  {} bytes", self.input_len);
        println!("  input buffer:{} bytes", self.max_input_size);
        println!("  iterations:  {}", self.iterations);
        println!("  repeats:     {}", self.runs.len());

        for (i, run) in self.runs.iter().enumerate() {
            self.print_run(i, run);
        }

        if self.runs.len() > 1 {
            self.print_aggregate();
        }
    }

    /// Prints the full detail for a single run.
    fn print_run(&self, index: usize, run: &RunResult) {
        println!();
        if self.runs.len() > 1 {
            println!("  run {}/{}:", index + 1, self.runs.len());
        }
        println!(
            "  boot + snapshot creation: {}",
            format_duration(run.boot_time)
        );
        println!("  steady-state (snapshot restore + target run):");
        println!("    execs/sec: {:.1}", run.execs_per_sec(self.iterations));
        println!("    exec time: {}", format_duration(run.total));
        println!(
            "    latency:   min {}  mean {}  median {}  p99 {}  max {}",
            format_duration(run.stats.min),
            format_duration(run.stats.mean),
            format_duration(run.stats.median),
            format_duration(run.stats.p99),
            format_duration(run.stats.max),
        );
        // Split the per-exec latency into the target's own guest runtime and the
        // Nyx machinery around it, so a change's effect on real target work is
        // visible separately from snapshot restore cost.
        println!(
            "    input execution: mean {}  median {}   (guest runtime)",
            format_duration(run.target.mean),
            format_duration(run.target.median),
        );
        println!(
            "    nyx overhead:    mean {}  median {}   (restore + reset + ipc; {:.0} dirty pages/exec)",
            format_duration(run.overhead.mean),
            format_duration(run.overhead.median),
            run.mean_dirty_pages,
        );
        println!(
            "    failed iterations: {} / {}",
            run.failed_iterations, self.iterations
        );
        print_crash_reports(&run.crash_reports);
        if let Some(cov) = &run.coverage {
            println!(
                "    coverage determinism: {:.1}% stable ({} / {} edges fluctuated)",
                cov.stable_pct(),
                cov.fluctuated_edges,
                cov.executed_edges,
            );
        }
    }

    /// Prints mean (and spread) of each metric across all runs.
    fn print_aggregate(&self) {
        let eps: Vec<f64> = self
            .runs
            .iter()
            .map(|r| r.execs_per_sec(self.iterations))
            .collect();
        let (eps_mean, eps_stddev) = mean_stddev(&eps);
        let eps_min = eps.iter().copied().fold(f64::INFINITY, f64::min);
        let eps_max = eps.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let total_failed_iterations: u64 = self.runs.iter().map(|r| r.failed_iterations).sum();
        let total_execs = self.iterations * self.runs.len();

        println!();
        println!("  aggregate over {} runs:", self.runs.len());
        println!(
            "    execs/sec: mean {eps_mean:.1}  stddev {eps_stddev:.1}  min {eps_min:.1}  max {eps_max:.1}"
        );
        println!(
            "    boot + snapshot: mean {}",
            format_duration(avg_duration(self.runs.iter().map(|r| r.boot_time)))
        );
        println!("    latency (mean across runs):");
        println!(
            "      min {}  mean {}  median {}  p99 {}  max {}",
            format_duration(avg_duration(self.runs.iter().map(|r| r.stats.min))),
            format_duration(avg_duration(self.runs.iter().map(|r| r.stats.mean))),
            format_duration(avg_duration(self.runs.iter().map(|r| r.stats.median))),
            format_duration(avg_duration(self.runs.iter().map(|r| r.stats.p99))),
            format_duration(avg_duration(self.runs.iter().map(|r| r.stats.max))),
        );
        println!(
            "    input execution (mean across runs): mean {}  median {}",
            format_duration(avg_duration(self.runs.iter().map(|r| r.target.mean))),
            format_duration(avg_duration(self.runs.iter().map(|r| r.target.median))),
        );
        println!(
            "    nyx overhead (mean across runs):     mean {}  median {}",
            format_duration(avg_duration(self.runs.iter().map(|r| r.overhead.mean))),
            format_duration(avg_duration(self.runs.iter().map(|r| r.overhead.median))),
        );
        println!("    failed iterations: {total_failed_iterations} / {total_execs}");

        // Pool the per-run tallies so a report that appears in several runs is
        // counted once, with its total.
        let mut pooled_reports: HashMap<String, u64> = HashMap::new();
        for (report, count) in self.runs.iter().flat_map(|r| &r.crash_reports) {
            *pooled_reports.entry(report.clone()).or_insert(0) += count;
        }
        print_crash_reports(&pooled_reports);

        // Each run measures its own snapshot's determinism; summing the counts
        // over runs gives a pooled stable percentage (an edge stable in every
        // run of every boot). Skip if no run produced a bitmap.
        let covs: Vec<CoverageSummary> = self.runs.iter().filter_map(|r| r.coverage).collect();
        if !covs.is_empty() {
            let pooled = CoverageSummary {
                executed_edges: covs.iter().map(|c| c.executed_edges).sum(),
                fluctuated_edges: covs.iter().map(|c| c.fluctuated_edges).sum(),
            };
            println!(
                "    coverage determinism: {:.1}% stable ({} / {} edges fluctuated, summed over runs)",
                pooled.stable_pct(),
                pooled.fluctuated_edges,
                pooled.executed_edges,
            );
        }
    }
}

/// Prints each distinct crash report and how many executions hit it. Prints
/// nothing when no execution failed.
fn print_crash_reports(reports: &HashMap<String, u64>) {
    for (report, count) in reports {
        println!("    [{count}x] {}", report.replace('\n', "\n      "));
    }
}

/// Formats a duration with a scale-appropriate unit (µs/ms/s).
// Nanosecond counts small enough to display never exceed f64's mantissa.
#[allow(clippy::cast_precision_loss)]
fn format_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000_000 {
        format!("{:.1} µs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.3} s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_scales_units() {
        assert_eq!(format_duration(Duration::from_nanos(500)), "0.5 µs");
        assert_eq!(format_duration(Duration::from_micros(250)), "250.0 µs");
        assert_eq!(format_duration(Duration::from_micros(1_500)), "1.50 ms");
        assert_eq!(format_duration(Duration::from_millis(1_500)), "1.500 s");
    }

    #[test]
    fn default_max_input_size_matches_afl_and_is_page_aligned() {
        // AFL++'s MAX_FILE, and a page multiple so it never trips the QEMU-Nyx
        // payload-buffer assertion.
        assert_eq!(DEFAULT_MAX_INPUT_SIZE, 1_048_576);
        assert_eq!(DEFAULT_MAX_INPUT_SIZE % NYX_PAGE_SIZE, 0);
    }

    #[test]
    fn validate_iterations_accepts_up_to_the_cap() {
        assert!(validate_iterations(0).is_err());
        assert_eq!(validate_iterations(1), Ok(1));
        assert_eq!(validate_iterations(DEFAULT_ITERATIONS), Ok(1000));
        assert_eq!(
            validate_iterations(MAX_ITERATIONS),
            Ok(usize::try_from(MAX_ITERATIONS).unwrap())
        );
    }

    #[test]
    fn validate_iterations_rejects_counts_past_the_cap() {
        // The sample vectors are preallocated from this count, so a stray extra
        // digit must be an error, not several GiB reserved up front.
        for n in [MAX_ITERATIONS + 1, 100_000_000, u64::MAX] {
            assert!(validate_iterations(n).is_err(), "{n}");
        }
    }

    #[test]
    fn validate_repeat_bounds_the_results_vector() {
        assert!(validate_repeat(0).is_err());
        assert_eq!(validate_repeat(1), Ok(1));
        assert_eq!(validate_repeat(MAX_REPEAT), Ok(MAX_REPEAT as usize));
        assert!(validate_repeat(MAX_REPEAT + 1).is_err());
        assert!(validate_repeat(u32::MAX).is_err());
    }

    #[test]
    fn validate_max_input_size_passes_a_size_the_input_fits() {
        // The size is used as given, never shrunk to the input: a smaller buffer
        // than the default is the point of the flag.
        assert_eq!(validate_max_input_size(4096, 1), Ok(4096));
        assert_eq!(validate_max_input_size(4096, 4092), Ok(4096));
        assert_eq!(
            validate_max_input_size(DEFAULT_MAX_INPUT_SIZE, 10),
            Ok(DEFAULT_MAX_INPUT_SIZE)
        );
        // Above AFL++'s default is allowed; the guest just has to have the RAM.
        assert_eq!(validate_max_input_size(4 << 20, 2 << 20), Ok(4 << 20));
    }

    #[test]
    fn validate_max_input_size_rejects_input_larger_than_the_buffer() {
        // An input filling the buffer exactly leaves no room for the length
        // prefix, so it is rejected just like one past the buffer.
        for len in [4093usize, 4096, 4097, usize::MAX] {
            let err = validate_max_input_size(4096, len).unwrap_err();
            assert!(err.contains("--max-input-size"), "{err}");
        }
        // The default buffer carries anything four bytes short of 1 MiB.
        let max_len = DEFAULT_MAX_INPUT_SIZE - PAYLOAD_HEADER_SIZE;
        assert!(validate_max_input_size(DEFAULT_MAX_INPUT_SIZE, max_len as usize).is_ok());
        assert!(validate_max_input_size(DEFAULT_MAX_INPUT_SIZE, max_len as usize + 1).is_err());
    }

    #[test]
    fn validate_max_input_size_rejects_a_non_page_aligned_size() {
        // These reach QEMU-Nyx verbatim and would abort the VM on its
        // page-multiple assertion, so they are caught here instead.
        for size in [1u32, 4095, 4097, 1_000_000] {
            let err = validate_max_input_size(size, 0).unwrap_err();
            assert!(err.contains("multiple"), "{err}");
        }
        // Zero is page-aligned by arithmetic but is not a usable buffer.
        assert!(validate_max_input_size(0, 0).is_err());
    }

    #[test]
    fn load_input_defaults_to_zero_byte() {
        let args = BenchExecArgs {
            path: PathBuf::from("unused.toml"),
            input: None,
            iterations: DEFAULT_ITERATIONS,
            repeat: 1,
            worker_id: 0,
            cpu: None,
            max_input_size: DEFAULT_MAX_INPUT_SIZE,
            timeout_secs: BENCH_TIMEOUT_SECS,
            no_build: false,
        };
        assert_eq!(load_input(&args).unwrap(), vec![0u8]);
    }

    #[test]
    fn load_input_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("seed");
        fs::write(&input_path, b"hello").unwrap();
        let args = BenchExecArgs {
            path: PathBuf::from("unused.toml"),
            input: Some(input_path),
            iterations: DEFAULT_ITERATIONS,
            repeat: 1,
            worker_id: 0,
            cpu: None,
            max_input_size: DEFAULT_MAX_INPUT_SIZE,
            timeout_secs: BENCH_TIMEOUT_SECS,
            no_build: false,
        };
        assert_eq!(load_input(&args).unwrap(), b"hello");
    }

    #[test]
    fn load_input_reports_missing_file() {
        let args = BenchExecArgs {
            path: PathBuf::from("unused.toml"),
            input: Some(PathBuf::from("/no/such/input")),
            iterations: DEFAULT_ITERATIONS,
            repeat: 1,
            worker_id: 0,
            cpu: None,
            max_input_size: DEFAULT_MAX_INPUT_SIZE,
            timeout_secs: BENCH_TIMEOUT_SECS,
            no_build: false,
        };
        assert!(load_input(&args).is_err());
    }

    #[test]
    fn classify_count_buckets_hits() {
        // AFL++'s live count classes, as bucket indices: 0, 1, [2..3], [4..7],
        // [8..15], [16..31], [32..63], [64..127], [128..255].
        assert_eq!(classify_count(0), 0);
        assert_eq!(classify_count(1), 1);
        assert_eq!(classify_count(2), 2);
        assert_eq!(classify_count(3), 2);
        assert_eq!(classify_count(4), 3);
        assert_eq!(classify_count(7), 3);
        assert_eq!(classify_count(8), 4);
        assert_eq!(classify_count(15), 4);
        assert_eq!(classify_count(31), 5);
        assert_eq!(classify_count(63), 6);
        assert_eq!(classify_count(64), 7);
        assert_eq!(classify_count(127), 7);
        assert_eq!(classify_count(255), 8);
        // Every raw count lands in exactly one class, and the classes only ever
        // step upward: a change of class is what flags an unstable edge.
        for count in 0..=u8::MAX {
            assert!(classify_count(count) <= classify_count(count.saturating_add(1)));
        }
    }

    #[test]
    fn coverage_flags_two_vs_three_bucket_change() {
        // 2 and 3 land in different buckets under the retired OLD table but the
        // same bucket under AFL++'s live table; pin the live behaviour so a
        // 2<->3 edge counts as stable.
        let mut tracker = CoverageTracker::new(1);
        tracker.record(&[2]);
        tracker.record(&[3]);
        assert_eq!(tracker.summary().fluctuated_edges, 0);
    }

    #[test]
    fn coverage_stable_when_bitmaps_identical() {
        let mut tracker = CoverageTracker::new(4);
        for _ in 0..5 {
            tracker.record(&[0, 3, 0, 10]);
        }
        let summary = tracker.summary();
        assert_eq!(summary.executed_edges, 2);
        assert_eq!(summary.fluctuated_edges, 0);
        assert!((summary.stable_pct() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn coverage_flags_edges_that_change_bucket() {
        let mut tracker = CoverageTracker::new(3);
        tracker.record(&[5, 5, 0]);
        // Edge 0 stays in the same bucket (4..=7 -> 4); edge 1 jumps a bucket
        // (4 -> 32); edge 2 lights up only now (0 -> executed and fluctuated).
        tracker.record(&[7, 40, 1]);
        let summary = tracker.summary();
        assert_eq!(summary.executed_edges, 3);
        assert_eq!(summary.fluctuated_edges, 2);
    }

    #[test]
    fn coverage_ignores_within_bucket_jitter() {
        let mut tracker = CoverageTracker::new(1);
        // 100 and 101 both bucket to 64, so this is not instability.
        tracker.record(&[100]);
        tracker.record(&[101]);
        assert_eq!(tracker.summary().fluctuated_edges, 0);
    }

    #[test]
    fn coverage_no_hits_is_fully_stable() {
        let mut tracker = CoverageTracker::new(2);
        tracker.record(&[0, 0]);
        let summary = tracker.summary();
        assert_eq!(summary.executed_edges, 0);
        assert_eq!(summary.fluctuated_edges, 0);
        assert!((summary.stable_pct() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn bench_workdir_is_removed_on_drop() {
        let base = tempfile::tempdir().unwrap();
        let path = {
            let workdir = BenchWorkdir::create(base.path(), 0).unwrap();
            let p = workdir.path().to_path_buf();
            assert!(p.exists());
            p
        };
        assert!(!path.exists());
    }

    #[test]
    fn bench_workdir_is_unique_per_run_index() {
        let base = tempfile::tempdir().unwrap();
        let a = BenchWorkdir::create(base.path(), 0).unwrap();
        let b = BenchWorkdir::create(base.path(), 1).unwrap();
        assert_ne!(a.path(), b.path());
    }
}
