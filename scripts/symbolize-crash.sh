#!/bin/bash
#
# Symbolize a crash report from the CLN fuzzer.
#
# Usage: ./scripts/symbolize-crash.sh <scenario> <crash-log>
#
# The crash log contains unsymbolized ASan/UBSan/signal reports with addresses
# like (binary+0xOFFSET). This script resolves them to source file:line using
# llvm-symbolizer inside the Docker builder stage (which has debug info).
#
# Example:
#   ./scripts/symbolize-crash.sh encrypted_bytes crash.log

set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <scenario> <crash-log>"
    echo ""
    echo "Arguments:"
    echo "  scenario   Scenario name (encrypted_bytes, noise, ir, init)"
    echo "  crash-log  File containing unsymbolized crash report"
    exit 1
fi

SCENARIO="$1"
CRASH_LOG="$2"
BUILDER_IMAGE="smite-cln-${SCENARIO}-builder"

if [ ! -f "$CRASH_LOG" ]; then
    echo "Error: crash log '$CRASH_LOG' not found"
    exit 1
fi

# Tag the builder stage so we can run llvm-symbolizer inside it.
if ! docker image inspect "$BUILDER_IMAGE" > /dev/null 2>&1; then
    echo "Building builder stage image..." >&2
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SMITE_DIR="$(dirname "$SCRIPT_DIR")"
    docker build --target builder -t "$BUILDER_IMAGE" \
        --build-arg "SCENARIO=$SCENARIO" \
        -f "$SMITE_DIR/workloads/cln/Dockerfile" "$SMITE_DIR" > /dev/null 2>&1
fi

# Regex matching (binary+offset) in crash frames.
BINARY_OFFSET_RE='\(([^+]+)\+(0x[0-9a-fA-F]+)\)'

# Collect offsets grouped by binary.
declare -A BINARY_OFFSETS
while IFS= read -r line; do
    if [[ "$line" =~ $BINARY_OFFSET_RE ]]; then
        binary="${BASH_REMATCH[1]}"
        offset="${BASH_REMATCH[2]}"
        BINARY_OFFSETS["$binary"]+="$offset "
    fi
done < "$CRASH_LOG"

if [ ${#BINARY_OFFSETS[@]} -eq 0 ]; then
    echo "No symbolizable frames found in crash log" >&2
    cat "$CRASH_LOG"
    exit 0
fi

# Resolve symbols using llvm-symbolizer inside the builder container.
declare -A RESOLVED
for binary in "${!BINARY_OFFSETS[@]}"; do
    offsets=(${BINARY_OFFSETS[$binary]})

    # llvm-symbolizer outputs pairs of lines (function, file:line:col) for each
    # address, including inlined functions. Blank lines separate addresses.
    result=$(docker run --rm --tmpfs /tmp:rw,exec,size=1g "$BUILDER_IMAGE" \
        llvm-symbolizer --obj="$binary" "${offsets[@]}" 2>/dev/null) || true

    # Parse output using blank lines as address boundaries.
    i=0
    func=""
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            ((i++)) || true
            continue
        fi
        if [ -z "$func" ]; then
            func="$line"
        else
            key="${binary}+${offsets[$i]}"
            entry="$func $line"
            # Skip duplicate inline entries (LLVM sometimes emits the same
            # function/source pair twice at certain optimization levels).
            if [ -n "${RESOLVED[$key]+x}" ]; then
                prev="${RESOLVED[$key]##*$'\n'}"
                if [ "$prev" != "$entry" ]; then
                    RESOLVED["$key"]+=$'\n'"$entry"
                fi
            else
                RESOLVED["$key"]="$entry"
            fi
            func=""
        fi
    done <<< "$result"
done

# Rewrite crash log with symbolized frames.
while IFS= read -r line; do
    if [[ "$line" =~ $BINARY_OFFSET_RE ]]; then
        key="${BASH_REMATCH[1]}+${BASH_REMATCH[2]}"
        if [ -n "${RESOLVED[$key]+x}" ]; then
            prefix="${line%%\(*}"
            first=true
            while IFS= read -r entry; do
                if $first; then
                    echo "${prefix}in $entry"
                    first=false
                else
                    printf "%*s%s\n" "${#prefix}" "" "in $entry"
                fi
            done <<< "${RESOLVED[$key]}"
            continue
        fi
    fi
    echo "$line"
done < "$CRASH_LOG"
