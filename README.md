<div align="center">

# 🦀 Rustagon

**Next-Generation Container Runtime Security Engine**

*100% Pure Rust • 100% AI-Generated Code (Zero Hand-Written Lines) • Powered by eBPF (Aya)*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Aya-green.svg)](https://aya-rs.dev/)
[![AI-Generated](https://img.shields.io/badge/Codebase-100%25%20AI%20Generated-purple.svg)]()
[![Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

</div>

---

## 🤖 The 100% AI-Driven Experiment

**Rustagon** is not just a security tool—it is a pioneer experiment in AI-Native Systems Engineering.

**Every single line of code in this repository (from eBPF kernel probes to AST parsers and Tokio async runtimes) was generated 100% by AI (Cursor, Claude Code, and OpenCode) without any manual coding.**

This project sets out to prove that state-of-the-art AI code generation can architect, implement, and optimize ultra-low-level Linux kernel infrastructure and complex systems software that matches strict production performance metrics.

---

## 💡 What is Rustagon?

**Rustagon** is a container runtime security engine rewritten entirely in **Rust** using the [Aya](https://aya-rs.dev/) eBPF framework as a drop-in replacement for **CNCF Falco**.

It delivers real-time threat detection, syscall tracing, and rule-based auditing for Kubernetes and Linux containers—without the legacy memory safety risks or heavy C++ runtime overhead of traditional security agents.

### Core Mission:
1. **0% Hand-Written Code**: Built completely through AI prompts, multi-agent review, and autonomous AI coding workflows.
2. **100% Pure Rust Stack**: Built using **Rust** for both userspace logic and kernel-space eBPF programs (via `aya` and `aya-ebpf`), with zero dependencies on legacy C++ libraries (`libscap` / `libsinsp`).
3. **100% Falco Test Suite Compatibility**: Designed to pass all official Falco end-to-end (E2E), rule engine, and AST syntax test suites.
4. **Equal or Superior Performance**: Reaches and exceeds Falco's throughput and memory metrics under high-volume event bursts.

---

## 🏗️ Architecture

```text
                  +-------------------------------------------------+
                  |              Falco Rules (YAML)                 |
                  +------------------------+------------------------+
                                           |
                                           v
                  +-------------------------------------------------+
                  |     Rustagon Engine (100% AI-Generated Rust)    |
                  |                                                 |
                  |   +-------------------+   +-----------------+   |
                  |   | Rule AST Evaluator|   | Process Tree    |   |
                  |   | (nom / pest)      |   | (DashMap Cache) |   |
                  |   +---------+---------+   +--------+--------+   |
                  |             ^                      ^            |
                  |             |                      |            |
                  |      +------+----------------------+-----+      |
                  |      |   K8s / Containerd Metadata Sync  |      |
                  |      +-----------------------------------+      |
                  +------------------------+------------------------+
                                           ^
                                           | Async RingBuffer Stream
                  === Kernel / Userspace Boundary ===================
                                           |
                  +------------------------+------------------------+
                  |         eBPF Drivers (Aya Rust / eBPF)          |
                  |                                                 |
                  |  +------------------+     +------------------+  |
                  |  | Tracepoints /    |     |  bpf_lsm Hooks   |  |
                  |  | Raw Tracepoints  |     |  (Enforcement)   |  |
                  |  +------------------+     +------------------+  |
                  +-------------------------------------------------+
