FROM debian:bookworm AS builder

# Build arguments
ARG LLVM_V=19
ARG BITCOIN_VERSION=30.3

ENV LLVM_V=${LLVM_V}

# Install LLVM toolchain (using modern key method without gnupg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    wget \
    ca-certificates
RUN mkdir -p /etc/apt/keyrings && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/keyrings/llvm.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/llvm.asc] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_V} main" > /etc/apt/sources.list.d/llvm.list

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-${LLVM_V} \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang-${LLVM_V}
ENV CXX=clang++-${LLVM_V}

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly && rustup default nightly

# Install cargo-afl for AFL instrumentation
RUN cargo install cargo-afl

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Build ldk-node-wrapper with AFL instrumentation.
# AFL_NO_CFG_FUZZING=1 prevents cargo-afl from setting --cfg fuzzing, which
# would enable simplified Poly1305 MAC in lightning's onion crypto and
# various test-only code paths. We want to fuzz the real production code.
WORKDIR /ldk-wrapper
COPY workloads/ldk/Cargo.toml workloads/ldk/Cargo.lock ./
COPY workloads/ldk/src/ src/
ENV AFL_NO_CFG_FUZZING=1
# The kAFL64-Hypervisor CPU model used by QEMU-Nyx (both KVM-PT and fallback mode) is based on
# Intel Haswell (2013), which predates AVX-512. It exposes up to x86-64-v3 (AVX2, FMA, BMI1/2)
# but not x86-64-v4 (AVX512F and friends). Building on a host with AVX-512 causes LLVM, especially
# LLVM 22+ in recent Rust nightlies, to emit 512-bit zmm instructions that the VM cannot execute,
# producing SIGILL on startup. Capping codegen to x86-64-v3 matches the VM's ceiling and keeps the
# build reproducible across all host CPUs.
# See: https://github.com/nyx-fuzz/QEMU-Nyx/blob/qemu-nyx-4.2.0/target/i386/cpu.c#L1975
ENV RUSTFLAGS="-C target-cpu=x86-64-v3"
RUN cargo afl build --release

# Copy smite workspace files and build all scenario binaries
WORKDIR /smite
COPY Cargo.toml Cargo.lock ./
COPY smite/ smite/
COPY smite-ir/ smite-ir/
COPY smite-ir-mutator/ smite-ir-mutator/
COPY smite-nyx-sys/ smite-nyx-sys/
COPY smitebot/ smitebot/
COPY smite-scenarios/ smite-scenarios/
RUN set -eu; for f in smite-scenarios/src/bin/ldk_*.rs; do \
        TARGET_PATH=/ldk-wrapper/target/release/ldk-node-wrapper \
            cargo build -p smite-scenarios --bin "$(basename $f .rs)" --release --features nyx; \
    done

# Build crash handler shared libraries, LD_PRELOADed into ldk-node-wrapper to
# report crashes immediately (before process teardown closes TCP sockets).
#   nyx-crash-handler.so  - reports crashes via Nyx hypercalls
#   crash-handler.so      - calls _exit(1), for local reproduction
RUN clang-${LLVM_V} -fPIC -DENABLE_NYX -DNO_PT_NYX -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /nyx-crash-handler.so && \
    clang-${LLVM_V} -fPIC -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /crash-handler.so

# Runtime image
FROM debian:bookworm-slim
ARG SCENARIO

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libgcc-s1 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy ldk-node-wrapper binary and crash handlers
COPY --from=builder /ldk-wrapper/target/release/ldk-node-wrapper /usr/local/bin/ldk-node-wrapper
COPY --from=builder /nyx-crash-handler.so /crash-handler.so /

# Copy bitcoind
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind

# Copy the ldk-scenario binary
COPY --from=builder /smite/target/release/ldk_${SCENARIO} /ldk-scenario

# Default to the local crash handler; init.sh overrides with the Nyx version.
ENV SMITE_CRASH_HANDLER=/crash-handler.so

# Copy the init script
COPY workloads/ldk/init.sh /init.sh
RUN chmod +x /init.sh /ldk-scenario

WORKDIR /
