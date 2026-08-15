#!/bin/bash
#
# Generate an HTML coverage report from a corpus of fuzz inputs.
#
# Usage: ./scripts/coverage-report.sh <target> <scenario> <corpus-dir> [output-dir]
#
# Targets:   lnd, cln, ldk, eclair
# Scenarios: encrypted_bytes, noise, ir, init
#
# This script:
# 1. Builds (if needed) a coverage-instrumented Docker image
# 2. Runs each corpus input through the target scenario
# 3. Merges coverage data and generates an HTML report
#
set -eu

if [ $# -lt 3 ]; then
    echo "Usage: $0 <target> <scenario> <corpus-dir> [output-dir]"
    echo ""
    echo "Arguments:"
    echo "  target      Target implementation (lnd, cln, ldk, eclair)"
    echo "  scenario    Scenario name (encrypted_bytes, noise, ir, init)"
    echo "  corpus-dir  Directory containing fuzz input files"
    echo "  output-dir  Output directory (default: ./<target>-<scenario>-coverage-report)"
    echo ""
    echo "Environment variables:"
    echo "  REBUILD=1   Force rebuild of Docker image"
    echo "  PARALLEL=N  Number of parallel jobs (default: number of CPU cores)"
    exit 1
fi

TARGET="$1"
SCENARIO="$2"

# Validate target.
case "$TARGET" in
    lnd|cln|ldk|eclair) ;;
    *)
        echo "Error: Unknown target '$TARGET'. Must be one of: lnd, cln, ldk, eclair"
        exit 1
        ;;
esac

# Docker image tag uses dashes (convention), scenario binary is per-target.
DOCKER_IMAGE="smite-${TARGET}-${SCENARIO}-coverage"
SCENARIO_BIN="/${TARGET}-scenario"

# Set coverage environment variables for docker run.
# All targets mount their per-input coverage directory at /covdata inside the
# container. The coverage tool writes to /covdata using its native format:
#   LND:    Go coverage -> /covdata/covcounters.* (GOCOVERDIR)
#   CLN:    LLVM profraw -> /covdata/coverage-*.profraw (LLVM_PROFILE_FILE)
#   LDK:    LLVM profraw -> /covdata/coverage-*.profraw (LLVM_PROFILE_FILE)
#   Eclair: JaCoCo exec -> /covdata/jacoco.exec (baked into Dockerfile)
COV_ENV=()
case "$TARGET" in
    lnd)     COV_ENV=(-e GOCOVERDIR=/covdata) ;;
    cln|ldk) COV_ENV=(-e LLVM_PROFILE_FILE="/covdata/coverage-%p_%m.profraw") ;;
    eclair)  ;;
esac

# Convert to absolute paths to prevent Docker from interpreting relative paths
# as named volumes
CORPUS_DIR="$(cd "$3" && pwd)"
OUTPUT_DIR="${4:-./${TARGET}-${SCENARIO}-coverage-report}"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

# Validate PARALLEL
MAX_JOBS="${PARALLEL:-$(nproc)}"
if ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]] || [ "$MAX_JOBS" -eq 0 ]; then
    echo "Error: PARALLEL must be a positive integer, got '$MAX_JOBS'"
    exit 1
fi

# Verify corpus directory exists
if [ ! -d "$CORPUS_DIR" ]; then
    echo "Error: Corpus directory '$CORPUS_DIR' does not exist"
    exit 1
fi

# Count inputs
INPUT_COUNT=$(find "$CORPUS_DIR" -maxdepth 1 -type f | wc -l)
if [ "$INPUT_COUNT" -eq 0 ]; then
    echo "Error: No input files found in '$CORPUS_DIR'"
    exit 1
fi

echo "Found $INPUT_COUNT input files in corpus"

# If docker runs as root, we need to set the --user flag to ensure the created
# coverage report is accessible to the current user. For rootless docker, the
# --user flag is unnecessary and causes permission issues.
DOCKER_USER=(--user "$(id -u):$(id -g)")
if docker info 2>/dev/null | grep -q "rootless"; then
    DOCKER_USER=()
fi

# Build coverage image if needed (use REBUILD=1 to force rebuild)
if [ "${REBUILD:-}" = "1" ] || ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SMITE_DIR="$(dirname "$SCRIPT_DIR")"

    echo "Building coverage Docker image..."
    docker build -t "$DOCKER_IMAGE" \
        --build-arg "SCENARIO=$SCENARIO" \
        -f "$SMITE_DIR/workloads/${TARGET}/Dockerfile.coverage" "$SMITE_DIR"
fi

# Create output directories (remove old data to avoid mixing with previous runs)
rm -rf "$OUTPUT_DIR/covdata" "$OUTPUT_DIR/merged" "$OUTPUT_DIR/html"
mkdir -p "$OUTPUT_DIR/covdata"
# LND merge step writes to a separate merged directory
[ "$TARGET" = "lnd" ] && mkdir -p "$OUTPUT_DIR/merged"

# Minimum expected Go coverage file size. Go's coverage runtime writes metadata
# first, then counters. Under high parallel load, processes may exit before
# counters are flushed, producing truncated files. We set this after the first
# input to detect truncated files in subsequent runs.
MIN_COV_SIZE=0

# Runs a single corpus input through the scenario and collects coverage data.
#
# Note: We mount the entire corpus directory because AFL++ filenames contain
# colons (e.g., id:000000,time:0) which conflict with Docker's -v syntax. Also
# each input gets its own coverage subdirectory to avoid filename collisions
# (CLN produces multiple profraw files per run for its subdaemon processes).
run_input() {
    local i="$1"
    local input_name="$2"
    local covdir="$OUTPUT_DIR/covdata/input-$i"
    local max_retries=3

    for ((attempt=0; attempt<max_retries; attempt++)); do
        rm -rf "$covdir"
        mkdir "$covdir"

        docker run --rm "${DOCKER_USER[@]}" \
            --tmpfs /tmp:rw,exec,size=1g \
            -v "$CORPUS_DIR:/corpus:ro" \
            -v "$covdir:/covdata" \
            -e SMITE_INPUT="/corpus/$input_name" \
            "${COV_ENV[@]}" \
            "$DOCKER_IMAGE" \
            "$SCENARIO_BIN" >/dev/null 2>&1 || true

        # Check if coverage data was produced
        if [ -n "$(ls -A "$covdir" 2>/dev/null)" ]; then
            # LND: also verify file size (Go coverage can be truncated under load)
            if [ "$TARGET" = "lnd" ]; then
                local covfile
                covfile=$(ls "$covdir"/covcounters.* 2>/dev/null | head -1)
                if [ -f "$covfile" ]; then
                    local size
                    size=$(stat -c%s "$covfile" 2>/dev/null || echo 0)
                    [ "$size" -ge "$MIN_COV_SIZE" ] && return 0
                fi
            else
                return 0
            fi
        fi

        # Retry with backoff
        sleep $((attempt + 1))
    done

    echo "Warning: input-$i ($input_name) coverage may be incomplete after $max_retries attempts" >&2
}

# Run first input to verify the Docker image works (and for LND, establish
# coverage file size baseline).
echo "Running first input as smoke test..."
FIRST_INPUT=$(find "$CORPUS_DIR" -maxdepth 1 -type f | head -1)
if [ -z "$FIRST_INPUT" ]; then
    echo "Error: No input files found"
    exit 1
fi
FIRST_NAME=$(basename "$FIRST_INPUT")
run_input 0 "$FIRST_NAME"

if [ -z "$(ls -A "$OUTPUT_DIR/covdata/input-0" 2>/dev/null)" ]; then
    echo "Error: First input produced no coverage data"
    exit 1
fi

if [ "$TARGET" = "lnd" ]; then
    # Establish baseline file size for truncation detection
    BASELINE_FILE=$(ls "$OUTPUT_DIR/covdata/input-0"/covcounters.* 2>/dev/null | head -1)
    BASELINE_SIZE=$(stat -c%s "$BASELINE_FILE")
    MIN_COV_SIZE=$((BASELINE_SIZE - 1000))
    echo "Baseline coverage file size: $BASELINE_SIZE bytes (min threshold: $MIN_COV_SIZE)"
else
    echo "Smoke test passed"
fi

echo "Processing remaining $((INPUT_COUNT - 1)) inputs with $MAX_JOBS parallel jobs..."

# Process remaining inputs in parallel with job limiting
i=1
active_jobs=0
for input in "$CORPUS_DIR"/*; do
    [ -f "$input" ] || continue
    INPUT_NAME=$(basename "$input")

    # Skip first input (already processed)
    if [ "$INPUT_NAME" = "$FIRST_NAME" ]; then
        continue
    fi

    # Run in background
    run_input "$i" "$INPUT_NAME" &
    active_jobs=$((active_jobs + 1))
    i=$((i + 1))

    # Limit parallelism
    if [ "$active_jobs" -ge "$MAX_JOBS" ]; then
        echo "Progress: $i/$INPUT_COUNT inputs started"
        wait -n 2>/dev/null || true
        active_jobs=$((active_jobs - 1))
    fi
done

# Wait for remaining jobs
echo "Waiting for remaining jobs to complete..."
wait

echo ""
echo "Merging coverage data and generating report..."

# Merge coverage data and generate report. Each target uses different coverage
# tools, so the merge step is necessarily target-specific.
case "$TARGET" in
    lnd)
        docker run --rm "${DOCKER_USER[@]}" \
            --tmpfs /tmp:rw,exec,size=1g \
            -v "$OUTPUT_DIR:/output" \
            -e GOCACHE=/tmp/go-cache \
            -e GOPATH=/tmp/go \
            "$DOCKER_IMAGE" \
            sh -c '
                set -eu

                COVDIRS=$(find /output/covdata -mindepth 1 -maxdepth 1 -type d | sort | tr "\n" "," | sed "s/,$//")
                if [ -z "$COVDIRS" ]; then
                    echo "Error: No coverage data found"
                    exit 1
                fi

                echo "Merging coverage data from $(echo "$COVDIRS" | tr "," "\n" | wc -l) directories..."
                go tool covdata merge -i="$COVDIRS" -o=/output/merged

                echo "Converting to text profile..."
                go tool covdata textfmt -i=/output/merged -o=/output/coverage.txt

                mkdir -p /output/html
                echo "Generating HTML report..."
                cd /lnd && go tool cover -html=/output/coverage.txt -o=/output/html/index.html
            '
        echo ""
        echo "Coverage report generated: $OUTPUT_DIR/html/index.html"
        ;;

    cln|ldk)
        docker run --rm "${DOCKER_USER[@]}" \
            --tmpfs /tmp:rw,exec,size=1g \
            -v "$OUTPUT_DIR:/output" \
            -e TARGET="$TARGET" \
            "$DOCKER_IMAGE" \
            sh -c '
                set -eu

                find /output/covdata -name "*.profraw" -type f > /tmp/profraw-list.txt
                PROFRAW_COUNT=$(wc -l < /tmp/profraw-list.txt)
                echo "Found $PROFRAW_COUNT profraw files"

                if [ "$PROFRAW_COUNT" -eq 0 ]; then
                    echo "Error: No profraw files found"
                    exit 1
                fi

                echo "Merging profraw files..."
                llvm-profdata merge -sparse -f /tmp/profraw-list.txt -o /output/merged.profdata

                # Build object list: primary binary + any additional instrumented
                # binaries (CLN has subdaemons and plugins).
                OBJECTS=""
                if [ "$TARGET" = "cln" ]; then
                    BIN=/usr/local/bin/lightningd
                    for bin in /usr/local/libexec/c-lightning/lightning_* \
                               /usr/local/libexec/c-lightning/plugins/*; do
                        [ -f "$bin" ] && OBJECTS="$OBJECTS -object=$bin"
                    done
                else
                    BIN=/usr/local/bin/ldk-node-wrapper
                fi

                echo "Generating HTML report..."
                llvm-cov show \
                    "$BIN" \
                    $OBJECTS \
                    --instr-profile=/output/merged.profdata \
                    --format=html \
                    --output-dir=/output/html \
                    --show-line-counts-or-regions \
                    --show-instantiations=false \
                    --ignore-filename-regex='/rustc/'
            '
        echo ""
        echo "Coverage report generated: $OUTPUT_DIR/html/index.html"
        ;;

    eclair)
        docker run --rm "${DOCKER_USER[@]}" \
            --tmpfs /tmp:rw,exec,size=1g \
            -v "$OUTPUT_DIR:/output" \
            "$DOCKER_IMAGE" \
            sh -c '
                set -eu

                find /output/covdata -name "jacoco.exec" -type f > /tmp/exec-list.txt
                EXEC_COUNT=$(wc -l < /tmp/exec-list.txt)
                echo "Found $EXEC_COUNT exec files"

                if [ "$EXEC_COUNT" -eq 0 ]; then
                    echo "Error: No JaCoCo exec files found"
                    exit 1
                fi

                MERGE_ARGS=""
                while IFS= read -r f; do
                    MERGE_ARGS="$MERGE_ARGS $f"
                done < /tmp/exec-list.txt

                echo "Merging exec files..."
                java -jar /jacococli.jar merge $MERGE_ARGS --destfile /output/merged.exec

                # Only pass fr.acinq JARs to --classfiles; scanning all of
                # /opt/eclair/lib fails because some dependency JARs (e.g.
                # BouncyCastle) have multi-release class entries that JaCoCo
                # cannot handle.
                CLASSFILES=""
                for jar in /opt/eclair/lib/eclair-*.jar \
                           /opt/eclair/lib/bitcoin-*.jar \
                           /opt/eclair/lib/secp256k1-kmp-jvm-*.jar; do
                    [ -f "$jar" ] && CLASSFILES="$CLASSFILES --classfiles $jar"
                done

                echo "Generating HTML report..."
                java -jar /jacococli.jar report /output/merged.exec \
                    $CLASSFILES \
                    --sourcefiles /eclair-src/eclair-core/src/main/scala \
                    --sourcefiles /eclair-src/eclair-node/src/main/scala \
                    --html /output/html \
                    --name "Eclair Coverage Report"
            '
        echo ""
        echo "Coverage report generated: $OUTPUT_DIR/html/index.html"
        ;;
esac
