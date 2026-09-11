FROM debian:bookworm AS builder

# Build arguments
ARG LLVM_V=19
ARG CLN_VERSION=v26.06.6
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
    autoconf \
    automake \
    libtool \
    clang-${LLVM_V} \
    lld-${LLVM_V} \
    llvm-${LLVM_V}-dev \
    libclang-rt-${LLVM_V}-dev \
    curl \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    libsqlite3-dev \
    libsodium-dev \
    libssl-dev \
    zlib1g-dev \
    gettext \
    jq \
    lowdown \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create unversioned symlinks for LLVM tools. lld is needed by AFL++ for LTO
# support; llvm-symbolizer is used by the crash symbolization script.
RUN ln -sf /usr/bin/ld.lld-${LLVM_V} /usr/bin/ld.lld && \
    ln -sf /usr/bin/llvm-symbolizer-${LLVM_V} /usr/bin/llvm-symbolizer

# Install AFL++ from source (need afl-clang-lto for LTO instrumentation).
# Builds just the compiler wrappers, not QEMU/Nyx support.
RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /AFLplusplus
WORKDIR /AFLplusplus
RUN CC=clang-${LLVM_V} CXX=clang++-${LLVM_V} \
    LLVM_CONFIG=llvm-config-${LLVM_V} \
    make -j$(nproc) && make install
RUN test -f /usr/local/lib/afl/afl-llvm-lto-instrumentlist.so

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly && rustup default nightly

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Clone CLN and build with AFL instrumentation.
RUN git clone --depth 1 --branch ${CLN_VERSION} --recurse-submodules \
    https://github.com/ElementsProject/lightning.git /cln
WORKDIR /cln
RUN pip3 install --break-system-packages mako
# Patch connectd to remove a 5s delay that occurs when disconnecting from peers.
# This delay causes CLN to become unresponsive on the connection for 5s, which
# kills our fuzzing speed when it occurs.
#
# The 5s timeout we need to remove occurs before connectd calls
# close_subd_timeout, which is the function that force-closes the subdaemon fd
# after an error message has been queued to the peer. In some cases the
# subdaemon does not exit on its own (e.g., openingd will not exit if it's in
# the middle of a funding flow), and we have to wait for the full 5s timeout
# before close_subd_timeout is called. The only benefit of waiting is to give
# the subdaemon time to queue any additional messages it wants to send after the
# error message. But for our fuzzing purposes, we don't care about messages
# after the error message -- once we receive the error we stop execution anyway.
#
# There's a separate 5s timeout that occurs before connectd force-closes the
# connection socket via close_peer_io_timeout. We do *not* want to remove that
# timeout since then the connection might get closed before we have a chance to
# read the messages leading up to the error message. The sed command below is
# designed to remove all of the relevant 5s timeouts while skipping the
# close_peer_io_timeout one that we want to retain.
#
# If CLN changes this code significantly in the future, we will need to update
# these commands accordingly.
RUN sed -i '/peer->to_peer/!s/time_from_sec(5)/time_from_sec(0)/' connectd/multiplex.c && \
    test "$(grep -c 'time_from_sec(0)' connectd/multiplex.c)" -eq 3 && \
    test "$(grep -c 'time_from_sec(5)' connectd/multiplex.c)" -eq 1 && \
    grep -A1 'time_from_sec(5)' connectd/multiplex.c | grep -q close_peer_io_timeout
# Reduce the block-polling interval from the 30s default to 2s. CLN only
# notices newly confirmed transactions when this poll runs, so shorten the
# interval to make block-related events available to scenarios promptly.
# FIXME: tune this value down after further experiments.
RUN sed -i 's/topo->poll_seconds = 30;/topo->poll_seconds = 2;/' lightningd/chaintopology.c && \
    test "$(grep -c 'topo->poll_seconds = 2;' lightningd/chaintopology.c)" -eq 1
# Add a `syncblocks` RPC command that forces CLN to poll for new blocks
# immediately instead of waiting for the polling timer. Scenarios can call it
# on demand after mining a block. This complements periodic polling: concurrent
# requests are coalesced, and polling still catches any blocks missed while CLN
# is processing a previous chain update.
COPY workloads/cln/patches/syncblocks.patch .
RUN git apply syncblocks.patch
# AFL_UBSAN_VERBOSE=1 gives us helpful UBSan reports instead of simply SIGILL.
ENV AFL_UBSAN_VERBOSE=1
RUN CC=afl-clang-lto ./configure --prefix=/usr/local --disable-rust \
    --enable-address-sanitizer --enable-ub-sanitizer
COPY workloads/cln/build-cln-lto.sh /tmp/
RUN chmod +x /tmp/build-cln-lto.sh && /tmp/build-cln-lto.sh

# Copy smite workspace files and build all scenario binaries
WORKDIR /smite
COPY Cargo.toml Cargo.lock ./
COPY smite/ smite/
COPY smite-ir/ smite-ir/
COPY smite-ir-mutator/ smite-ir-mutator/
COPY smite-nyx-sys/ smite-nyx-sys/
COPY smitebot/ smitebot/
COPY smite-scenarios/ smite-scenarios/
RUN set -eu; for f in smite-scenarios/src/bin/cln_*.rs; do \
        TARGET_MAP_SIZE=$(cat /tmp/total-map-size) \
            cargo build -p smite-scenarios --bin "$(basename $f .rs)" --release --features nyx; \
    done

# Build crash handler shared libraries, LD_PRELOADed into CLN to bypass its
# blocking crashdump signal handler. Two variants:
#   nyx-crash-handler.so  - reports crashes via Nyx hypercalls
#   crash-handler.so      - calls _exit(1), for local reproduction
# -DCATCH_SIGNALS is required: it overrides sigaction() to prevent CLN's
# crashdump handler from overwriting ASan/UBSan signal handlers. Without it,
# CLN's flush_and_exit() blocks for 10s on crashes. -DCATCH_SIGNALS also blocks
# ASan from installing its own signal handlers, but ASan's compile-time
# instrumentation still works.
RUN clang-${LLVM_V} -fPIC -DENABLE_NYX -DCATCH_SIGNALS -DNO_PT_NYX -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /nyx-crash-handler.so && \
    clang-${LLVM_V} -fPIC -DCATCH_SIGNALS -D_GNU_SOURCE \
    smite-nyx-sys/src/nyx-crash-handler.c -ldl -shared -o /crash-handler.so

# Runtime image
FROM debian:bookworm-slim
ARG SCENARIO

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    libgcc-s1 \
    libsqlite3-0 \
    libsodium23 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Copy CLN binaries (subdaemons and plugins in libexec/)
COPY --from=builder /usr/local/bin/lightningd /usr/local/bin/lightningd
COPY --from=builder /usr/local/bin/lightning-cli /usr/local/bin/lightning-cli
COPY --from=builder /usr/local/libexec/c-lightning/ /usr/local/libexec/c-lightning/

# Copy bitcoind
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind

# Copy crash handlers and cln-scenario binary
COPY --from=builder /nyx-crash-handler.so /crash-handler.so /
COPY --from=builder /smite/target/release/cln_${SCENARIO} /cln-scenario

# Default to the local crash handler; init.sh overrides with the Nyx version.
# ClnTarget forwards this as LD_PRELOAD on lightningd only, so it doesn't
# interfere with helper processes (lightning-cli).
ENV SMITE_CRASH_HANDLER=/crash-handler.so

# ASan options for CLN binaries (instrumented with -fsanitize=address):
#   abort_on_error=1  - call abort() on errors, triggering the crash handler
#   log_path          - write error details to file for crash handler to read
#   symbolize=0       - skip symbolization to maximize the chances of winning
#                       the race against snapshot reset. llvm-symbolizer can
#                       take hundreds of ms to run, which would likely cause the
#                       snapshot to reset before the crash is reported.
ENV ASAN_OPTIONS=abort_on_error=1:log_path=/tmp/asan.log:symbolize=0

# Copy the init script
COPY workloads/cln/init.sh /init.sh
RUN chmod +x /init.sh /cln-scenario

WORKDIR /
