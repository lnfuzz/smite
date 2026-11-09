# Smite

Smite is a coverage-guided fuzzing framework for Lightning Network implementations, derived from [fuzzamoto](https://github.com/dergoegge/fuzzamoto).

## Supported Targets

- [LND](https://github.com/lightningnetwork/lnd)
- [LDK](https://github.com/lightningdevkit/ldk-node)
- [CLN](https://github.com/ElementsProject/lightning)
- [Eclair](https://github.com/ACINQ/eclair)

## Prerequisites

- x86_64 architecture
- Modern Linux operating system
- Docker
- Rust toolchain
- tmux
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) built from source with Nyx mode

## Quick Start

Fuzzing campaigns are managed with [`smitebot`](smitebot/README.md). Run the commands below from the root of the smite repository.

```bash
# Install smitebot
cargo install --path smitebot

# Enable the KVM VMware backdoor (required for Nyx)
./scripts/enable-vmware-backdoor.sh
```

Create a campaign config, choosing a target (`lnd`, `ldk`, `cln`, or `eclair`) and a scenario (`encrypted_bytes`, `noise`, `init`, or `ir`):

```toml
# campaign.toml
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "/home/user/AFLplusplus"
smite_dir = "."
runners = 8
output_dir = "/tmp/smite-out"
sharedir = "/tmp/smite-nyx"
```

See [`smitebot/sample-campaign.toml`](smitebot/sample-campaign.toml) for all config options.

```bash
# Check host prerequisites
smitebot doctor campaign.toml

# Build the Docker image, create the Nyx sharedir, and start fuzzing
smitebot start campaign.toml
```

`smitebot start` launches one AFL++ instance per runner in a tmux session and prints the campaign ID (e.g., `lnd-encrypted_bytes-1767225600`) used by the other commands:

```bash
# Show the campaign's live dashboard
smitebot status <campaign-id>

# Stop the campaign
smitebot stop <campaign-id>
```

### IR Scenario

The `ir` scenario uses structured IR programs instead of raw byte inputs, with a custom AFL++ mutator. `smitebot` automatically sets the needed flags and environment variables for this scenario.

To print an IR input in readable form:

```bash
smitebot print-ir <input>
```

## Running Modes

### Nyx Mode

Uses the [Nyx hypervisor](https://nyx-fuzz.com/) for fast snapshot-based fuzzing.
AFL++ manages the fuzzing loop and coverage feedback. This is the mode `smitebot start` runs.

### Local Mode

This mode runs without Nyx and is used to reproduce and debug crashes.

#### Reproducing Crashes

When AFL++ finds a crash, replay it against the campaign's Docker image:

```bash
smitebot reproduce <campaign-id> -i /tmp/smite-out/<runner>/crashes/<crashing-input>
```

### Coverage Report Mode

Generate an HTML coverage report showing which parts of the target were exercised by a fuzzing corpus:

```bash
# Merge and minimize the corpora of all runners
smitebot corpus minimize <campaign-id> -o /tmp/smite-corpus

# Generate coverage report
./scripts/coverage-report.sh lnd encrypted_bytes /tmp/smite-corpus

# View the report
firefox ./lnd-encrypted_bytes-coverage-report/html/index.html
```

Minimizing keeps only inputs that add AFL++ edge coverage, which makes the report much faster to generate. To report on the full corpus instead, use `smitebot corpus merge <campaign-id> -o /tmp/smite-corpus`.

## Project Structure

```
smite/              # Core Rust library (runners, scenarios, noise protocol, BOLT messages)
smitebot/           # Automation CLI for fuzzing campaign orchestration
smite-ir/           # IR types, generators, and mutators for structured fuzzing programs
smite-ir-mutator/   # AFL++ custom mutator cdylib for IR programs
smite-nyx-sys/      # Nyx FFI bindings
smite-scenarios/    # Scenario implementations and target binaries
workloads/
  lnd/              # LND fuzzing workload (Dockerfile, init script)
  ldk/              # LDK fuzzing workload (Dockerfile, init script, ldk-node wrapper)
  cln/              # CLN fuzzing workload (Dockerfile, init script)
  eclair/           # Eclair fuzzing workload (Dockerfile, init script, instrumentation agent)
scripts/
  setup-nyx.sh              # Helper to create Nyx sharedirs
  enable-vmware-backdoor.sh # Enable KVM VMware backdoor for Nyx
  coverage-report.sh        # Generate a coverage report for any scenario
  symbolize-crash.sh        # Symbolize CLN crash report stack traces
```
