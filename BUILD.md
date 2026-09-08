# Rustagon Build Guide

This document explains the Rustagon workspace structure and how to build and develop the project.

## Workspace Structure

Rustagon uses a Cargo workspace with 5 crates:

### 1. **rustagon-common** (`rustagon-common/`)
Shared data structures and event definitions used across all crates.

**Key Components:**
- Event type definitions (EventType enum)
- Event headers and structured data (OpenEvent, SyscallEvent, etc.)
- All structures use `#[repr(C)]` for kernel-userspace binary compatibility
- String helper utilities for C-compatible string handling
- Validation functions

**No External Dependencies** - pure data definitions

**Use Case:**
- Shared across eBPF programs and userspace daemon
- Ensures consistent event format across all components

---

### 2. **rustagon-ebpf** (`rustagon-ebpf/`)
Pure Rust eBPF kernel programs using aya-ebpf framework.

**Key Components:**
- Tracepoint probes (sys_enter_open, sys_enter_openat)
- KProbe handlers (syscall tracing)
- RingBuffer output for events

**Design Constraints:**
- ❌ NO dynamic memory allocation
- ❌ NO Vec, String, HashMap, Box, or any heap allocation
- ✅ Stack-allocated fixed-size structures only
- ✅ All structures tagged with `#[repr(C)]`
- ✅ Compiles to eBPF bytecode (bpfel64-unknown-none target)

**Dependencies:**
- `aya-ebpf` - eBPF framework
- `rustagon-common` - shared types

**Build Target:** `bpfel64-unknown-none`

```bash
# Build eBPF programs
cargo xtask build-ebpf

# Or manually
cargo build --target bpfel64-unknown-none -p rustagon-ebpf --release
```

---

### 3. **rustagon-parser** (`rustagon-parser/`)
Falco YAML rule parsing and AST evaluation engine.

**Key Components:**
- YAML rule file parser using serde_yaml
- Rule macro expansion
- List definitions
- Simple AST evaluator for conditions

**Dependencies:**
- `serde_yaml` - YAML parsing
- `nom` - Parser combinator library
- `rustagon-common` - event types

**Design:**
- Parses Falco YAML rule format
- Compiles rules to AST
- Evaluates conditions against events
- Extensible for complex expression parsing

```bash
cargo test -p rustagon-parser
```

---

### 4. **rustagon-core** (`rustagon-core/`)
Userspace daemon for event capture and processing.

**Key Components:**
- **daemon.rs** - Main orchestrator
- **ringbuf.rs** - Ringbuffer consumer (reads events from eBPF)
- **runner.rs** - Event processor (evaluates rules)

**Design Principles:**
- ✅ 100% async using Tokio runtime
- ✅ Lock-free event channels (tokio::sync::mpsc)
- ✅ No blocking I/O operations
- ✅ Graceful shutdown handling
- ✅ Configurable worker pool

**Dependencies:**
- `aya` - eBPF loader and userspace API
- `tokio` - async runtime
- `crossbeam` - lock-free data structures
- `tracing` - observability
- `clap` - CLI argument parsing
- `rustagon-common`, `rustagon-parser`

**Running:**
```bash
# Build
cargo build --release -p rustagon-core

# Run (requires root for eBPF)
sudo cargo run --release -p rustagon-core -- -r rules.yaml

# With debug logging
RUST_LOG=debug sudo cargo run --release -p rustagon-core
```

---

### 5. **xtask** (`xtask/`)
Build orchestration and helper tasks.

**Key Commands:**
```bash
# Build eBPF programs
cargo xtask build-ebpf

# Build release version
cargo xtask build-ebpf --release

# Check without optimization
cargo xtask check-ebpf
```

**Why xtask?**
- Standardized Rust build task runner
- Handles cross-compilation (eBPF requires different target)
- Separates build concerns from main Cargo.toml
- CI/CD friendly

---

## Build Requirements

### System Requirements
- Rust 1.80+
- Linux 5.8+ (eBPF support)
- LLVM 12+ (for eBPF compilation)
- Clang 12+

### Install Build Tools
```bash
# Add eBPF target
rustup target add bpfel64-unknown-none

# Install llvm-tools
rustup component add llvm-tools-preview

# For Arch Linux
pacman -S llvm clang

# For Ubuntu/Debian
apt-get install llvm clang libclang-dev
```

---

## Building the Project

### Full Build
```bash
# Build everything (userspace + eBPF)
cargo build --release

# Includes:
# - rustagon-common library
# - rustagon-ebpf kernel programs
# - rustagon-parser library
# - rustagon-core daemon binary
# - xtask build tool
```

### Build Specific Components
```bash
# eBPF programs only
cargo xtask build-ebpf --release

# Userspace daemon only
cargo build --release -p rustagon-core

# Parser library
cargo build --release -p rustagon-parser

# Common library
cargo build --release -p rustagon-common
```

---

## Testing

```bash
# Test all crates
cargo test

# Test specific crate
cargo test -p rustagon-parser
cargo test -p rustagon-common

# Test with logging
RUST_LOG=debug cargo test -- --nocapture

# Run specific test
cargo test string_conversion
```

---

## Development Workflow

### 1. Modify eBPF Program
```bash
# Edit rustagon-ebpf/src/lib.rs
# Build eBPF only
cargo xtask build-ebpf
```

### 2. Modify Event Definitions
```bash
# Edit rustagon-common/src/lib.rs
# Automatically picked up by eBPF and userspace
cargo build --release
```

### 3. Modify Userspace Logic
```bash
# Edit rustagon-core/src/*.rs
# Rebuild daemon
cargo build --release -p rustagon-core
```

### 4. Modify Rule Parser
```bash
# Edit rustagon-parser/src/*.rs
# Test changes
cargo test -p rustagon-parser
cargo build --release -p rustagon-parser
```

---

## Constraints & Design Rules

### Rule 1: Pure Rust (No C/C++ Dependencies)
- ✅ Use `aya` and `aya-ebpf` for eBPF
- ❌ Never use `libbpf-sys`, `libscap`, `libsinsp`
- Validates in: dependency audit, CI checks

### Rule 2: Async-First Userspace
- ✅ All I/O must be async (tokio::*)
- ✅ Use lock-free channels for ITC
- ❌ No `std::thread::sleep()`, `std::fs::read()` in async context
- Validates in: code review, runtime behavior

### Rule 3: C-Compatible Data Structures
- ✅ All kernel-userspace types must use `#[repr(C)]`
- ❌ No dynamic allocation in eBPF
- ✅ Fixed-size stack-allocated arrays only
- Validates in: compile-time checks, eBPF verifier

---

## Troubleshooting

### eBPF Build Fails
```bash
# Check target is installed
rustup target list | grep bpfel64

# If missing, install it
rustup target add bpfel64-unknown-none

# Check LLVM tools
rustup component list | grep llvm-tools
```

### "error: linker `cc` not found"
```bash
# Install build essentials
# Ubuntu/Debian:
sudo apt-get install build-essential

# Arch:
pacman -S base-devel

# macOS (for cross-compilation):
brew install llvm
```

### Permission Denied Running rustagon
```bash
# eBPF programs require root
sudo ./target/release/rustagon -r rules.yaml

# Or use cargo with sudo
sudo -E cargo run --release -p rustagon-core
```

---

## Performance Considerations

### eBPF Program Size
- Keep kernel programs minimal
- Complex logic belongs in userspace
- Use userspace ringbuffer consumer for filtering

### Event Processing
- Worker threads scale with number of CPU cores
- Default: 4 workers (configurable)
- Lock-free channels minimize contention

### Memory Usage
- eBPF ringbuffer: 256KB default (configurable)
- Userspace: Tokio runtime ~50MB
- Event buffers scale with load

---

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: rustup target add bpfel64-unknown-none
      - run: apt-get install -y llvm clang
      - run: cargo build --release
      - run: cargo test
```

---

## Next Steps

1. Read [README.md](README.md) for architecture overview
2. Check [.cursor/rules.md](.cursor/rules.md) for development constraints
3. Review `rustagon-common/src/lib.rs` for event definitions
4. Study eBPF implementation in `rustagon-ebpf/src/lib.rs`
5. Explore rule parsing in `rustagon-parser/src/`
6. Run the daemon: `sudo cargo run --release -p rustagon-core`

