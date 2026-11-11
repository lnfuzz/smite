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
# -XX:TieredStopAtLevel=1: Use only the C1 JIT compiler, skipping C2 compilation
#   entirely. C2 runs expensive optimizations in background threads which get
#   repeated every time we restore the VM snapshot, reducing fuzzing speed.
#
# -Djava.library.path: Where EclairSanCov loads the JNI library that maps the
#   AFL shared memory its probes write to.
export JAVA_OPTS="-XX:TieredStopAtLevel=1 -Djava.library.path=/usr/local/lib"

/eclair-scenario > /init.log 2>&1
