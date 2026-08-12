#!/usr/bin/env python3
"""
Smite Fuzzing Evaluation Script

This script automates the rigorous statistical evaluation of an experimental fuzzer
configuration against a baseline, inspired by the framework from Klees et al. (2018).

It is designed to evaluate any feature that impacts coverage-over-time capabilities
(e.g., new mutators, custom schedulers, dictionary extraction, or seed selection).
The only prerequisite is variable isolation: every configuration parameter must be
identical between the baseline and the experimental configuration except for the
specific feature being tested.

Reference: https://github.com/morehouse/smite/issues/115

Requirements:
    pip install numpy pandas matplotlib seaborn scipy statsmodels tabulate

Expected Directory Structure:
The script expects a root directory containing the baseline and experimental subdirectories.
Each configuration must contain identical target subdirectories, which in turn hold
the trial directories containing AFL++ output.

<root_dir>/
├── configuration_1/                   # e.g., 'baseline'
│   ├── target_1/                      # e.g., 'cln'
│   │   ├── trial-01/
│   │   │   └── afl-out/default/       # Contains fuzzer_stats, plot_data, fuzz_bitmap
│   │   ├── trial-02/
│   │   └── ...                        # Any number of trials (automatically counted)
│   └── target_2/                      # e.g., 'lnd'
└── configuration_2/                   # e.g., 'experimental'
    ├── target_1/
    └── target_2/

Expected Output:
The script will create a `results/` directory inside the provided root directory containing:
- evaluation_report.md: A detailed Markdown report with summary statistics, adjusted
  p-values, effect sizes, an interpretation guide, and embedded visualizations.
- evaluation_metrics.csv: A complete data table of the summary statistics for external analysis.
- <target>_boxplot.png: Box plots comparing the final edge coverage distributions.
- <target>_auc_boxplot.png: Box plots comparing the Area Under Curve (exploration speed).
- <target>_time_series.png: Line charts showing median coverage over time with IQR bands.

Usage:
    python smite-evaluation.py <path_to_smite_evaluation_dir> <baseline_dir_name> <experimental_dir_name> [--hours <hours>]

Examples:
    # Run strictly, ensuring all trials completed within 5% of each other
    python smite-evaluation.py ./smite-evaluation baseline experimental

    # Evaluate strictly up to 12 hours (fails if any trial ended before ~11.4h)
    python smite-evaluation.py ./smite-evaluation baseline experimental --hours 12

    # Force evaluation at the shortest common timeframe
    python smite-evaluation.py ./smite-evaluation baseline experimental --hours min
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from statsmodels.stats.multitest import multipletests

# Apply clean visual styling for all generated plots
sns.set_style("whitegrid")


def validate_and_find_data(root_dir, config_a, config_b):
    """
    Scans the root directory to find configs, targets, and trial paths.
    Throws errors if the structure doesn't match the expected layout.
    """
    if not os.path.exists(root_dir):
        raise FileNotFoundError(f"Root directory '{root_dir}' does not exist.")

    path_a = os.path.join(root_dir, config_a)
    path_b = os.path.join(root_dir, config_b)

    if not os.path.isdir(path_a):
        raise FileNotFoundError(
            f"Baseline configuration directory '{config_a}' not found in {root_dir}"
        )
    if not os.path.isdir(path_b):
        raise FileNotFoundError(
            f"Experimental configuration directory '{config_b}' not found in {root_dir}"
        )

    print(
        f"[*] Configurations: Baseline (A) = {config_a}, Experimental (B) = {config_b}"
    )

    # Find targets
    targets_a = set(os.listdir(path_a))
    targets_b = set(os.listdir(path_b))

    if targets_a != targets_b:
        raise ValueError(
            f"Target mismatch! {config_a} has {targets_a}, but {config_b} has {targets_b}"
        )

    targets = sorted(list(targets_a))
    print(f"[*] Detected Targets: {targets}")

    data_paths = {config_a: {}, config_b: {}}

    # Validate trials and files
    for config in [config_a, config_b]:
        for target in targets:
            target_path = os.path.join(root_dir, config, target)
            trials = [
                d
                for d in os.listdir(target_path)
                if os.path.isdir(os.path.join(target_path, d))
            ]

            valid_trials = []
            for trial in trials:
                base_out = os.path.join(target_path, trial, "afl-out", "default")
                if not os.path.exists(base_out):
                    base_out = os.path.join(target_path, trial)

                req_files = ["plot_data", "fuzzer_stats", "fuzz_bitmap"]
                if all(os.path.exists(os.path.join(base_out, f)) for f in req_files):
                    valid_trials.append(base_out)
                else:
                    print(
                        f"[!] Warning: Missing required files in {os.path.join(target_path, trial)}. Skipping."
                    )

            data_paths[config][target] = valid_trials
            print(f"    - {config}/{target}: found {len(valid_trials)} valid trials")

    return targets, data_paths


def parse_plot_data(filepath):
    """Parses plot_data and returns (times_in_hours, coverage)."""
    with open(filepath, "r") as f:
        header_line = f.readline().strip()

    if not header_line:
        return np.array([0.0]), np.array([0.0])

    header = [col.strip() for col in header_line.lstrip("#").split(",")]
    df = pd.read_csv(
        filepath, comment="#", sep=",", header=None, names=header, skipinitialspace=True
    )

    if len(df) == 0:
        return np.array([0.0]), np.array([0.0])

    if "relative_time" not in header or "edges_found" not in header:
        raise ValueError(
            f"AFL++ >= 3.10c required. plot_data must contain 'relative_time' and 'edges_found'. Found: {header}"
        )

    # Coerce to float to prevent string errors
    times = pd.to_numeric(df["relative_time"], errors="coerce").fillna(0).values
    coverage = pd.to_numeric(df["edges_found"], errors="coerce").fillna(0).values

    # relative_time is already absolute seconds since fuzzer start. Convert directly to hours.
    relative_times_hrs = times / 3600.0

    return relative_times_hrs, coverage


def parse_fuzzer_stats(filepath):
    """Extracts execs_per_sec from fuzzer_stats."""
    with open(filepath, "r") as f:
        for line in f:
            if "execs_per_sec" in line:
                return float(line.split(":")[1].strip())
    return 0.0


def get_commit_info(root_dir, config_name):
    """Reads the saved commit metadata from the orchestrator."""
    commit_file = os.path.join(root_dir, config_name, "latest_commit.txt")
    if os.path.exists(commit_file):
        with open(commit_file, "r") as f:
            return f.read().strip()
    return "Unknown commit"


def calculate_union_coverage(trial_paths):
    """
    Performs bitwise-AND across all trial bitmaps to calculate multi-core union coverage.

    NOTE ON AFL++ BITMAP SEMANTICS:
    AFL++ initializes the virgin bitmap with 0xff (255) to represent unvisited edges.
    When an edge is hit, the corresponding byte is updated to a value < 0xff (hit count buckets).
    Because 0xff means "uncovered" and < 0xff means "covered", finding the true union
    of covered edges across multiple concurrent instances requires a bitwise-AND operation,
    not a logical OR. (e.g., 0xff & 0x80 = 0x80, preserving the covered state).
    """
    bitmaps = []
    expected_size = None
    for path in trial_paths:
        bmp_path = os.path.join(path, "fuzz_bitmap")
        bmp = np.fromfile(bmp_path, dtype=np.uint8)
        if expected_size is None:
            expected_size = len(bmp)
        elif len(bmp) != expected_size:
            print(
                f"[!] Warning: Bitmap size mismatch in {bmp_path}. Expected {expected_size}, got {len(bmp)}"
            )
            continue
        bitmaps.append(bmp)

    if not bitmaps:
        return 0

    union_bmp = np.bitwise_and.reduce(bitmaps, axis=0)
    covered_edges = np.sum(union_bmp < 255)
    return covered_edges


def vargha_delaney_a12(u_stat, n_a, n_b):
    """Calculates the Vargha-Delaney A12 effect size."""
    if n_a == 0 or n_b == 0:
        return 0.5
    return u_stat / (n_a * n_b)


def resolve_eval_hours(
    target, global_min_hrs, global_max_hrs, requested_hours, tolerance=0.05
):
    """Enforces the tolerance limit and resolves the strict evaluation boundary."""
    threshold = 1.0 - tolerance
    tolerance_percentage = int(tolerance * 100)

    if requested_hours is None:
        if global_min_hrs < threshold * global_max_hrs:
            raise ValueError(
                f"[!] Fuzzer instability detected in target '{target}'. "
                f"Shortest trial ended at {global_min_hrs:.2f}h, max was {global_max_hrs:.2f}h. "
                f"This exceeds the {tolerance_percentage}% acceptable variance. "
                f"Run with --hours=min to force evaluation at the shortest common timeframe."
            )
        return global_min_hrs

    elif requested_hours.lower() == "min":
        return global_min_hrs

    else:
        try:
            target_hrs = float(requested_hours)
        except ValueError:
            raise ValueError(
                f"[!] Invalid --hours value: '{requested_hours}'. Must be a number or 'min'."
            )
        if global_min_hrs < threshold * target_hrs:
            raise ValueError(
                f"[!] Fuzzer instability detected in target '{target}'. "
                f"Shortest trial ended at {global_min_hrs:.2f}h, but requested evaluation time is {target_hrs:.2f}h. "
                f"This exceeds the {tolerance_percentage}% acceptable variance. "
                f"Run with --hours=min to force evaluation at the shortest common timeframe."
            )
        # Clamp to global_min_hrs to guarantee LOCF is never utilized
        return min(target_hrs, global_min_hrs)


def generate_plots(
    results_dir,
    target,
    eval_hours,
    grid_times,
    interpolated_series,
    cov_a,
    cov_b,
    auc_a,
    auc_b,
    config_a,
    config_b,
):
    """Generates and saves the Boxplots and Time Series charts for a target."""
    n_a, n_b = len(cov_a), len(cov_b)

    # --- Plotting 1: Final Coverage Boxplots ---
    plt.figure(figsize=(8, 6))
    sns.boxplot(data=[cov_a, cov_b], palette="Set2")
    plt.xticks([0, 1], [f"{config_a}\n(n={n_a})", f"{config_b}\n(n={n_b})"])
    plt.title(f"{target} - Final Edge Coverage ({eval_hours:.1f}h)")
    plt.suptitle(
        "Box = Middle 50% (IQR), Line = Median, Whiskers = 1.5x IQR",
        fontsize=10,
        color="gray",
    )
    plt.ylabel("Edges Found")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, f"{target}_boxplot.png"), dpi=300)
    plt.close()

    # --- Plotting 2: AUC Boxplots ---
    plt.figure(figsize=(8, 6))
    sns.boxplot(data=[auc_a, auc_b], palette="Set2")
    plt.xticks([0, 1], [f"{config_a}\n(n={n_a})", f"{config_b}\n(n={n_b})"])
    plt.title(f"{target} - Area Under Curve (AUC)")
    plt.suptitle(
        "Box = Middle 50% (IQR), Line = Median, Whiskers = 1.5x IQR",
        fontsize=10,
        color="gray",
    )
    plt.ylabel("Cumulative Coverage × Time")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, f"{target}_auc_boxplot.png"), dpi=300)
    plt.close()

    # --- Plotting 3: Median Coverage over Time with IQR Bands ---
    plt.figure(figsize=(10, 6))
    colors = {config_a: "blue", config_b: "orange"}

    for config in [config_a, config_b]:
        ts_matrix = np.array(interpolated_series[config])
        if ts_matrix.shape[0] == 0:
            continue

        med_line = np.median(ts_matrix, axis=0)
        p25 = np.percentile(ts_matrix, 25, axis=0)
        p75 = np.percentile(ts_matrix, 75, axis=0)

        label_str = f"{config} (n={len(interpolated_series[config])})"
        plt.plot(
            grid_times, med_line, label=label_str, color=colors[config], linewidth=2
        )
        plt.fill_between(grid_times, p25, p75, color=colors[config], alpha=0.2)

    plt.title(f"{target} - Median Coverage Over Time (with IQR bounds)")
    plt.xlabel("Time (Hours)")
    plt.ylabel("Edges Found")
    plt.xlim([0, eval_hours])
    plt.ylim(bottom=0)
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, f"{target}_time_series.png"), dpi=300)
    plt.close()


def write_evaluation_report(
    report_path, df_results, config_a, config_b, commit_a, commit_b, targets
):
    """Writes the final comprehensive Markdown evaluation report."""

    # Order columns for clean Markdown display
    view_cols = [
        "Target",
        "Duration (h)",
        "n (Baseline)",
        "n (Exp.)",
        "Median Cov. (Baseline)",
        "Median Cov. (Exp.)",
        "Adj. p-value (Cov.)",
        "Â12 (Cov.)",
        "Median AUC (Baseline)",
        "Median AUC (Exp.)",
        "Adj. p-value (AUC)",
        "Â12 (AUC)",
        "Union Cov. (Baseline)",
        "Union Cov. (Exp.)",
        "Execs/s (Baseline)",
        "Execs/s (Exp.)",
    ]
    df_results_view = df_results[view_cols]

    with open(report_path, "w") as f:
        f.write("# Fuzzing Evaluation Report\n\n")
        f.write(
            f"**Configuration A (Baseline):** `{config_a}` *(Commit: {commit_a})*\n"
        )
        f.write(
            f"**Configuration B (Experimental):** `{config_b}` *(Commit: {commit_b})*\n\n"
        )

        f.write("## 1. Summary Statistics\n\n")
        pd.set_option("display.float_format", lambda x: "%.3f" % x)
        f.write(df_results_view.to_markdown(index=False))
        f.write(
            "\n\n*A comprehensive version of this table including raw P-values and "
            "Interquartile Ranges (IQRs) is available in `evaluation_metrics.csv`.*\n\n"
        )

        f.write("## 2. Interpretation Guide\n\n")
        f.write(
            "Use the generated matrix above to objectively evaluate the experimental "
            "configuration. For full methodology, see the [Smite Fuzzing Evaluation Framework]"
            "(https://github.com/morehouse/smite/issues/115).\n\n"
        )

        f.write("### Key Metrics\n\n")
        f.write(
            "- **`Adj. p-value`**: Mann-Whitney U test corrected for multiple targets via "
            "Holm-Bonferroni. Controls false-positive rate to ≤ 5% across all targets.\n"
        )
        f.write(
            "- **`Â12`**: Probability that a random B trial outperforms a random A trial. "
            "`0.5` = no difference; `0.7` = B wins 70% of pairings. Always read alongside "
            "the p-value.\n"
        )
        f.write(
            "- **`IQR`**: Spread of the middle 50% of trials. A much larger IQR in B suggests "
            "a few outlier runs may be inflating the median.\n"
        )
        f.write(
            "- **`AUC`**: Coverage *speed* — how much was discovered and how early. "
            "Useful when final coverage is similar between configurations.\n"
        )
        f.write(
            "- **Union Coverage**: Union of all trial bitmaps; the coverage ceiling for a "
            "multi-core deployment. Descriptive only, cannot be statistically tested.\n"
        )
        f.write(
            "- **`Execs/s`**: A large drop in B without a coverage gain means the new feature "
            "is too expensive.\n\n"
        )

        f.write("### Reading the Results\n\n")
        f.write("| Adj. p | `Â12` | Conclusion |\n")
        f.write("|---|---|---|\n")
        f.write(
            "| < 0.05 | > 0.5 | Meaningful improvement. Check IQRs are comparable, then merge. |\n"
        )
        f.write(
            "| < 0.05 | ~0.5 | Significant but negligible. Check if worth the added complexity. |\n"
        )
        f.write(
            "| > 0.05 | > 0.6 | Promising but underpowered. Re-run with more trials (e.g., 50). |\n"
        )
        f.write(
            "| > 0.05 | ~0.5 | No effect. Try an advanced snapshot or ground-truth evaluation. |\n"
        )
        f.write(
            "| any | < 0.5 | B underperforms A. If significant, reject or redesign the feature. |\n\n"
        )

        f.write(
            "> **Time-series caveat:** If the IQR bands overlap for most of the campaign and "
            "only diverge near the end, treat the final-coverage result cautiously — late "
            "divergence may reflect noise rather than a sustained advantage.\n\n"
        )

        f.write("## 3. Visualizations\n\n")
        f.write(
            "*Note: In the box plots below, the central box represents the Interquartile Range (IQR, "
            "the middle 50% of trials), demonstrating the consistency of the fuzzer's performance. "
            "The internal line represents the median.*\n\n"
        )

        # Embed images directly into the markdown report
        for target in targets:
            f.write(f"### Target: {target}\n\n")

            f.write(f"#### Median Coverage Over Time\n\n")
            f.write(f"![{target} Time Series]({target}_time_series.png)\n\n")

            f.write(f"#### Distribution Comparisons\n\n")
            f.write(f"| Final Edge Coverage | Area Under Curve (Speed) |\n")
            f.write(f"|:---:|:---:|\n")
            f.write(
                f"| ![{target} Boxplot]({target}_boxplot.png) | "
                f"![{target} AUC]({target}_auc_boxplot.png) |\n\n"
            )
            f.write("---\n\n")


def process_data(
    root_dir, config_a, config_b, targets, data_paths, requested_hours=None
):
    """Extracts metrics, computes statistics, and generates visualizations/reports."""
    results_dir = os.path.join(root_dir, "results")
    os.makedirs(results_dir, exist_ok=True)

    commit_a = get_commit_info(root_dir, config_a)
    commit_b = get_commit_info(root_dir, config_b)

    summary_stats = []
    p_values_cov_raw = []
    p_values_auc_raw = []

    for target in targets:
        print(f"\n[*] Processing Target: {target}")

        target_data = {config_a: {}, config_b: {}}
        raw_time_series = {config_a: [], config_b: []}

        global_max_hrs = 0.0
        global_min_hrs = float("inf")

        # Parse all data and find dynamic max and min times
        for config in [config_a, config_b]:
            target_data[config] = {"final_cov": [], "auc": [], "execs": [], "union": 0}

            for path in data_paths[config][target]:
                times, covs = parse_plot_data(os.path.join(path, "plot_data"))
                if len(times) > 0:
                    trial_end = times[-1]
                    global_max_hrs = max(global_max_hrs, trial_end)
                    global_min_hrs = min(global_min_hrs, trial_end)

                execs = parse_fuzzer_stats(os.path.join(path, "fuzzer_stats"))

                target_data[config]["execs"].append(execs)
                raw_time_series[config].append((times, covs))

            target_data[config]["union"] = calculate_union_coverage(
                data_paths[config][target]
            )

        if global_min_hrs == float("inf"):
            print(f"[!] Insufficient data for {target}. Skipping stats.")
            continue

        # Enforce tolerance check and resolve eval_hours
        eval_hours = resolve_eval_hours(
            target, global_min_hrs, global_max_hrs, requested_hours, tolerance=0.05
        )

        grid_times = np.linspace(0, eval_hours, 1000)
        interpolated_series = {config_a: [], config_b: []}

        # Extract metrics, interpolate, and calculate standardized AUC
        for config in [config_a, config_b]:
            for times, covs in raw_time_series[config]:
                if len(times) == 0:
                    continue

                # Interpolate to standardize the time axis
                interp_cov = np.interp(grid_times, times, covs)
                interpolated_series[config].append(interp_cov)

                # Extract final coverage exactly at the normalized eval_hours boundary
                final_cov = interp_cov[-1]

                # Calculate standardized AUC over the uniform grid (edges * hours)
                auc = np.trapezoid(y=interp_cov, x=grid_times)

                target_data[config]["final_cov"].append(final_cov)
                target_data[config]["auc"].append(auc)

        cov_a = target_data[config_a]["final_cov"]
        cov_b = target_data[config_b]["final_cov"]
        auc_a = target_data[config_a]["auc"]
        auc_b = target_data[config_b]["auc"]
        n_a, n_b = len(cov_a), len(cov_b)

        if n_a == 0 or n_b == 0:
            print(f"[!] Insufficient data for {target}. Skipping stats.")
            continue

        # Compute Statistics (Coverage)
        u_stat_cov, p_raw_cov = stats.mannwhitneyu(
            cov_b, cov_a, alternative="two-sided"
        )
        a12_cov = vargha_delaney_a12(u_stat_cov, n_b, n_a)
        p_values_cov_raw.append(p_raw_cov)

        # Compute Statistics (AUC)
        u_stat_auc, p_raw_auc = stats.mannwhitneyu(
            auc_b, auc_a, alternative="two-sided"
        )
        a12_auc = vargha_delaney_a12(u_stat_auc, n_b, n_a)
        p_values_auc_raw.append(p_raw_auc)

        summary_stats.append(
            {
                "Target": target,
                "Duration (h)": eval_hours,
                "n (Baseline)": n_a,
                "n (Exp.)": n_b,
                "Median Cov. (Baseline)": np.median(cov_a),
                "Median Cov. (Exp.)": np.median(cov_b),
                "IQR Cov. (Baseline)": stats.iqr(cov_a),
                "IQR Cov. (Exp.)": stats.iqr(cov_b),
                "Raw p-value (Cov.)": p_raw_cov,
                "Â12 (Cov.)": a12_cov,
                "Median AUC (Baseline)": np.median(auc_a),
                "Median AUC (Exp.)": np.median(auc_b),
                "IQR AUC (Baseline)": stats.iqr(auc_a),
                "IQR AUC (Exp.)": stats.iqr(auc_b),
                "Raw p-value (AUC)": p_raw_auc,
                "Â12 (AUC)": a12_auc,
                "Union Cov. (Baseline)": target_data[config_a]["union"],
                "Union Cov. (Exp.)": target_data[config_b]["union"],
                "Execs/s (Baseline)": np.median(target_data[config_a]["execs"]),
                "Execs/s (Exp.)": np.median(target_data[config_b]["execs"]),
            }
        )

        # Generate visual plots for this target
        generate_plots(
            results_dir,
            target,
            eval_hours,
            grid_times,
            interpolated_series,
            cov_a,
            cov_b,
            auc_a,
            auc_b,
            config_a,
            config_b,
        )

    # --- Multiple Comparisons Correction (Holm-Bonferroni) ---
    if len(p_values_cov_raw) > 0:
        reject_cov, p_adj_cov, _, _ = multipletests(
            p_values_cov_raw, alpha=0.05, method="holm"
        )
        reject_auc, p_adj_auc, _, _ = multipletests(
            p_values_auc_raw, alpha=0.05, method="holm"
        )

        for i, stat in enumerate(summary_stats):
            stat["Adj. p-value (Cov.)"] = p_adj_cov[i]
            stat["Sig_Cov"] = reject_cov[i]
            stat["Adj. p-value (AUC)"] = p_adj_auc[i]
            stat["Sig_AUC"] = reject_auc[i]

    # --- Generate Markdown Report & CSV Export ---
    if not summary_stats:
        print("[!] No data processed. Reports not generated.")
        return

    df_results = pd.DataFrame(summary_stats)

    # Save everything to CSV
    csv_path = os.path.join(results_dir, "evaluation_metrics.csv")
    df_results.to_csv(csv_path, index=False)

    report_path = os.path.join(results_dir, "evaluation_report.md")
    write_evaluation_report(
        report_path, df_results, config_a, config_b, commit_a, commit_b, targets
    )

    print(f"\n[*] Evaluation complete. Results saved to {results_dir}")
    print(f"    - Open {report_path} to interpret the campaign.")
    print(f"    - Metric data exported to {csv_path}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Smite Fuzzing Campaign Evaluation Script"
    )
    parser.add_argument(
        "root_dir",
        type=str,
        help="Path to the smite-evaluation root directory.",
    )
    parser.add_argument(
        "baseline_dir_name",
        type=str,
        help="Name of the baseline configuration directory (e.g., 'baseline').",
    )
    parser.add_argument(
        "experimental_dir_name",
        type=str,
        help="Name of the experimental configuration directory (e.g., 'experimental').",
    )
    parser.add_argument(
        "--hours",
        type=str,
        default=None,
        help="Target duration in hours, or 'min' to enforce the shortest common timeframe.",
    )

    args = parser.parse_args()

    tgts, data = validate_and_find_data(
        args.root_dir, args.baseline_dir_name, args.experimental_dir_name
    )
    process_data(
        args.root_dir,
        args.baseline_dir_name,
        args.experimental_dir_name,
        tgts,
        data,
        args.hours,
    )
