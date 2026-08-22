# eclipse-temurin:21 provides JDK 21
FROM eclipse-temurin:21 AS builder

# Build arguments
ARG ECLAIR_VERSION=v0.14.1
ARG BITCOIN_VERSION=31.1

# Install build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    maven \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Download and install Bitcoin Core
WORKDIR /tmp
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    tar -xzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/bitcoind && \
    mv bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli && \
    rm -rf bitcoin-${BITCOIN_VERSION}*

# Clone and build Eclair.
RUN git clone --depth 1 --branch ${ECLAIR_VERSION} https://github.com/ACINQ/eclair.git /eclair-src
WORKDIR /eclair-src
# Make eclair react to new blocks faster so scenarios see block events
# with minimal latency: poll bitcoind's ZMQ socket every 50ms instead
# of 1s, and process each block immediately instead of after 2s.
RUN sed -i 's/timers\.startSingleTimer(TickNewBlock, 2 seconds)/context.self ! TickNewBlock/' eclair-core/src/main/scala/fr/acinq/eclair/blockchain/bitcoind/ZmqWatcher.scala && \
    test "$(grep -c 'context.self ! TickNewBlock' eclair-core/src/main/scala/fr/acinq/eclair/blockchain/bitcoind/ZmqWatcher.scala)" -eq 2 && \
    sed -i 's/scheduleOnce(1 second, self, Symbol("checkMsg"))/scheduleOnce(50 milliseconds, self, Symbol("checkMsg"))/' eclair-core/src/main/scala/fr/acinq/eclair/blockchain/bitcoind/zmq/ZMQActor.scala && \
    test "$(grep -c 'scheduleOnce(50 milliseconds, self, Symbol("checkMsg"))' eclair-core/src/main/scala/fr/acinq/eclair/blockchain/bitcoind/zmq/ZMQActor.scala)" -eq 1
RUN ./mvnw package -DskipTests -pl eclair-node -am

# Unzip the Eclair distribution to /opt/eclair/.
# /opt/ is used instead of /usr/local/ because eclair-node.sh uses relative
# paths (../lib/) to locate its JARs; splitting bin/ from lib/ would break it.
RUN find eclair-node/target -name "eclair-node-*-bin.zip" \
        -exec unzip {} -d /opt \; && \
    mv /opt/eclair-node-* /opt/eclair

# Build the eclair-sancov Java agent.
COPY workloads/eclair/eclair-sancov/ /eclair-sancov/
WORKDIR /eclair-sancov
RUN mvn package

# Compile the JNI shared library that maps the AFL shared memory segment.
# JAVA_HOME is set by the eclipse-temurin base image.
RUN cc -shared -fPIC \
    -I"${JAVA_HOME}/include" \
    -I"${JAVA_HOME}/include/linux" \
    src/main/c/shmutil.c \
    -o /usr/local/lib/libeclair-sancov.so

# Count instrumentable Eclair methods to determine TARGET_MAP_SIZE.
# EclairEdgeCounter scans the same fr/acinq/eclair/ methods that
# EclairTransformer will instrument, so the count matches exactly.
RUN java -cp target/eclair-sancov-0.0.0.jar EclairEdgeCounter \
    $(find /opt/eclair/lib -name "*.jar" | tr '\n' ' ') \
    > /tmp/eclair-edge-count.txt && \
    echo "Eclair edge count: $(cat /tmp/eclair-edge-count.txt)"

# Copy smite workspace files and build all scenario binaries
WORKDIR /smite
COPY Cargo.toml Cargo.lock ./
COPY smite/ smite/
COPY smite-ir/ smite-ir/
COPY smite-ir-mutator/ smite-ir-mutator/
COPY smite-nyx-sys/ smite-nyx-sys/
COPY smitebot/ smitebot/
COPY smite-scenarios/ smite-scenarios/
RUN set -eu; for f in smite-scenarios/src/bin/eclair_*.rs; do \
        TARGET_MAP_SIZE=$(cat /tmp/eclair-edge-count.txt) \
            cargo build -p smite-scenarios --bin "$(basename $f .rs)" --release --features nyx; \
    done

# Build JVM crash handler shared libraries, LD_PRELOADed into the JVM to
# report crashes before atexit handlers close TCP sockets. Two variants:
#   nyx-jvm-crash-handler.so - reports crashes via Nyx hypercalls
#   jvm-crash-handler.so     - writes /tmp/smite-crash.log for local mode
RUN cc -shared -fPIC -DENABLE_NYX -DNO_PT_NYX \
    smite-nyx-sys/src/jvm-crash-handler.c -o /nyx-jvm-crash-handler.so && \
    cc -shared -fPIC \
    smite-nyx-sys/src/jvm-crash-handler.c -o /jvm-crash-handler.so

# Runtime image.
#
# Uses the full JDK (not -jre) so `jcmd` is available: after warmup the harness
# runs `jcmd <pid> Compiler.directives_add` to freeze the JIT (block new
# compilation while keeping warmed code) before the snapshot.
FROM eclipse-temurin:21
ARG SCENARIO

# Install curl for Eclair readiness polling in EclairTarget::query_info().
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Eclair distribution (bin/eclair-node.sh + lib/*.jar)
COPY --from=builder /opt/eclair /opt/eclair

# Copy Bitcoin Core binaries
COPY --from=builder /usr/local/bin/bitcoind /usr/local/bin/bitcoind
COPY --from=builder /usr/local/bin/bitcoin-cli /usr/local/bin/bitcoin-cli

# Copy coverage agent and JNI shared library
COPY --from=builder /eclair-sancov/target/eclair-sancov-0.0.0.jar /eclair-sancov.jar
COPY --from=builder /usr/local/lib/libeclair-sancov.so /usr/local/lib/libeclair-sancov.so

# Copy crash handlers and eclair scenario binary
COPY --from=builder /nyx-jvm-crash-handler.so /jvm-crash-handler.so /
COPY --from=builder /smite/target/release/eclair_${SCENARIO} /eclair-scenario

# Default to the local crash handler; init.sh overrides with the Nyx version.
ENV SMITE_CRASH_HANDLER=/jvm-crash-handler.so

# Copy init script
COPY workloads/eclair/init.sh /init.sh
RUN chmod +x /init.sh /eclair-scenario

ENV PATH="/opt/eclair/bin:${PATH}"

WORKDIR /
