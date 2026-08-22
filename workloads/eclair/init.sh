#!/bin/sh

# This script is executed inside the VM by the Nyx fuzzer

set -eu

# Run the Eclair fuzzing harness
export SMITE_NYX=1
export JAVA_HOME=/opt/java/openjdk
export PATH=$PATH:/usr/local/bin:/opt/eclair/bin:$JAVA_HOME/bin

# Override the default crash handler with the Nyx version, which reports
# crashes via Nyx hypercalls instead of writing to a file.
export SMITE_CRASH_HANDLER=/nyx-jvm-crash-handler.so

# JVM tuning for Nyx fuzzing performance. JAVA_OPTS is picked up by
# eclair-node.sh and passed to the JVM.
#
# -XX:TieredStopAtLevel=1: Use only the C1 JIT compiler, skipping C2. C2 measured
#   ~28% fewer execs/sec here: its speculative optimizations are tuned to the
#   fixed warmup path, so varied fuzzing inputs trip uncommon traps and deopt to
#   the interpreter each restore. C1 doesn't speculate, staying robust across
#   inputs with a more compact code cache.
#
# -javaagent: Coverage agent that instruments bytecode and writes edge counters
#   to AFL shared memory via JNI.
export JAVA_OPTS="-XX:TieredStopAtLevel=1 -javaagent:/eclair-sancov.jar -Djava.library.path=/usr/local/lib"

/eclair-scenario > /init.log 2>&1
