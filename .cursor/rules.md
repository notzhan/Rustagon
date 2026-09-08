# Rustagon Project Development Rules

## Rule 1: Prohibit C/C++ Dependencies (100% Pure Rust Requirement)

### Objective
Eliminate legacy system security vulnerabilities and ensure memory safety throughout the entire codebase.

### Constraints
- ❌ **STRICTLY FORBIDDEN**: Any dependency on C/C++ libraries including:
  - `libbpf-sys` (libbpf C bindings)
  - `libscap` / `libsinsp` (Falco's C++ library)
  - `libaudit` (Linux audit C library)
  - Any raw FFI bindings to C/C++ system libraries
  - Any `-sys` crates that are direct C/C++ wrappers

- ✅ **MANDATORY**: Use only pure Rust implementations:
  - `aya` crate for userspace eBPF management
  - `aya-ebpf` crate for kernel-space eBPF program development
  - `libc` only for minimal POSIX type definitions (not function calls)
  - Pure Rust alternatives for all system interactions

### Examples
```rust
// ❌ FORBIDDEN
use libbpf_sys::*;
use libscap::capture::*;

// ✅ CORRECT
use aya::maps::RingBuf;
use aya_ebpf::programs::TracePoint;
use aya_ebpf::helpers;
```

### Kernel-Userspace Communication
- Kernel eBPF programs: Must use `aya-ebpf`
- Userspace event consumption: Must use `aya::maps::RingBuf` or `aya::maps::PerfBuffer`
- All syscall tracing: Implement directly in Rust eBPF using tracepoints or kprobes

### Validation
- Code review must verify no `extern "C"` declarations for C library functions
- CI/CD pipeline must audit `Cargo.lock` for forbidden dependencies
- Architecture review meetings must confirm pure Rust design decisions

---

## Rule 2: Mandatory Async-First Userspace Design

### Objective
Ensure scalability, responsiveness, and efficient resource utilization in userspace components.

### Constraints

#### Async Runtime
- ✅ **MANDATORY**: Use `tokio` runtime for all userspace async operations
- ✅ **MANDATORY**: All I/O operations must be non-blocking
- ❌ **FORBIDDEN**: Blocking operations on the async task pool
  - No `std::thread::sleep()` in async context
  - No `std::fs::read()` in async context
  - No blocking socket operations in async tasks

#### Example
```rust
// ❌ FORBIDDEN
async fn process_events() {
    std::thread::sleep(Duration::from_secs(1)); // BLOCKS RUNTIME
    std::fs::read_to_string("config.yaml"); // BLOCKS RUNTIME
}

// ✅ CORRECT
async fn process_events() {
    tokio::time::sleep(Duration::from_secs(1)).await;
    tokio::fs::read_to_string("config.yaml").await.unwrap();
}
```

#### Inter-Thread Communication (ITC)
- ✅ **PREFERRED**: Lock-free queues for thread communication:
  - `tokio::sync::mpsc` (multiple-producer, single-consumer)
  - `tokio::sync::broadcast` (broadcasting to multiple consumers)
  - `crossbeam::queue::SegQueue` (concurrent MPMC queue)
  - `crossbeam::channel` (multi-producer, multi-consumer channels)

- ❌ **MINIMIZE**: Mutex-based synchronization:
  - Use only when absolutely necessary for shared mutable state
  - Prefer `tokio::sync::RwLock` over `std::sync::Mutex` in async context
  - Hold locks for minimal duration to prevent contention

#### Example
```rust
// ❌ AVOID (if possible)
let shared_state = Arc::new(Mutex::new(EventQueue::new()));
let queue = shared_state.lock().unwrap();
queue.push(event);

// ✅ CORRECT (lock-free)
let (tx, rx) = tokio::sync::mpsc::channel(10000);
tx.send(event).await.unwrap();

// Receiver in another task
while let Some(event) = rx.recv().await {
    process_event(event).await;
}
```

#### Event Processing
- ✅ Each event processor must be an independent async task
- ✅ Events flow through lock-free channels between tasks
- ✅ Use `tokio::spawn` for concurrent event handlers
- ✅ Implement graceful shutdown with cancellation tokens

#### Validation
- Code review must verify no blocking operations in async context
- Benchmark reports must demonstrate throughput and latency metrics
- Thread safety must be validated using `cargo +nightly clippy -- -W clippy::undocumented_unsafe_blocks`

---

## Rule 3: C-Compatible Kernel-Userspace Data Structures

### Objective
Enable safe, efficient data sharing between kernel and userspace without serialization overhead.

### Constraints

#### Representation
- ✅ **MANDATORY**: All shared data structures MUST use `#[repr(C)]`:
  ```rust
  #[repr(C)]
  pub struct EventHeader {
      pub timestamp: u64,
      pub pid: u32,
      pub uid: u32,
  }
  ```

- ❌ **FORBIDDEN**: Default Rust representation for kernel-shared types
  ```rust
  // ❌ WRONG - Default Rust repr
  pub struct Event {
      pub timestamp: u64,
      pub pid: u32,
  }
  
  // ✅ CORRECT - C-compatible repr
  #[repr(C)]
  pub struct Event {
      pub timestamp: u64,
      pub pid: u32,
  }
  ```

#### Memory Allocation (Kernel-Space)

- ❌ **STRICTLY FORBIDDEN** in eBPF kernel programs:
  - `Vec::new()` / `Vec::with_capacity()`
  - `HashMap::new()` / `BTreeMap::new()`
  - `String::new()` / `String::from()`
  - Any heap allocation via `Box::new()`
  - `alloc::*` module functions

- ✅ **MANDATORY** for kernel-space structures:
  - Stack-allocated fixed-size arrays: `[u8; SIZE]`
  - Fixed-size primitives: `u64`, `u32`, `[u8; 256]`, etc.
  - No dynamic sizing

#### Example
```rust
// In rustagon-ebpf/src/lib.rs (kernel program)

// ❌ FORBIDDEN
pub fn read_filename() {
    let mut path = String::new(); // Heap allocation
    // ... 
}

// ✅ CORRECT
#[repr(C)]
pub struct FileEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub filename: [u8; 256], // Fixed-size stack array
}

pub fn capture_open_event() -> FileEvent {
    let event: FileEvent = unsafe { core::mem::zeroed() };
    event.timestamp = helpers::ktime_get_ns();
    event.filename[0..6].copy_from_slice(b"/tmp\0");
    event
}
```

#### Data Sharing Mechanism
- Use `aya::maps::RingBuf` or `aya::maps::PerfBuffer` for kernel → userspace
- All events transferred must fit in `#[repr(C)]` structure
- Userspace deserializes directly from the ringbuffer without parsing overhead

#### Type Compatibility
- Ensure `size_of::<EventType>()` is deterministic
- Use `#[repr(C, packed)]` if memory alignment must match exact byte offsets
- Document byte layouts in comments for critical structures

#### Validation
```bash
# Verify repr(C) on all shared types
cargo +nightly clippy -- -W clippy::missing_repr_for_struct

# Verify no dynamic allocation in eBPF
cargo build --target bpfel64-unknown-none -p rustagon-ebpf
# (Any heap allocation will fail eBPF bytecode verification)

# Verify memory layout consistency
cargo test --lib -- --nocapture --test-threads=1
```

---

## Enforcement & Review Checklist

### Pre-Commit
- [ ] No forbidden C/C++ dependencies added to `Cargo.toml`
- [ ] All new async code uses `tokio::` not blocking I/O
- [ ] All inter-task communication uses lock-free channels
- [ ] All kernel-userspace shared types have `#[repr(C)]`
- [ ] eBPF code contains no heap allocation

### Code Review
- [ ] Verify pure Rust implementation choices
- [ ] Confirm async-first design in userspace
- [ ] Check data structure compatibility between kernel and userspace
- [ ] Validate eBPF program compiles without allocation errors

### CI/CD Pipeline
- [ ] Dependency audit: forbidden crates check
- [ ] eBPF bytecode validation (no unverified heap allocation)
- [ ] Performance benchmark: throughput and latency within targets
- [ ] Memory profile: verify constant memory usage with varying event load

---

## References

- [Aya eBPF Framework](https://aya-rs.dev/)
- [Falco Documentation](https://falco.org/)
- [Tokio Async Runtime](https://tokio.rs/)
- [Crossbeam Concurrency](https://docs.rs/crossbeam/)
- [Rust `#[repr(C)]` Documentation](https://doc.rust-lang.org/reference/type-layout.html#the-c-representation)
- [Linux eBPF in Rust](https://aya-rs.dev/book/)
