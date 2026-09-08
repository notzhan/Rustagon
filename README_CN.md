<div align="center">

# 🦀 Rustagon

**下一代容器运行时安全引擎**

*100% 纯 Rust · 100% AI 生成代码（零手写行数）· 由 eBPF（Aya）驱动*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Aya-green.svg)](https://aya-rs.dev/)
[![AI-Generated](https://img.shields.io/badge/Codebase-100%25%20AI%20Generated-purple.svg)]()
[![Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

</div>

---

## 🤖 100% AI 驱动的实验

**Rustagon** 不仅仅是一个安全工具——它是 AI 原生系统工程的先驱性实验。

**这个代码库中的每一行代码（从 eBPF 内核探针到 AST 解析器和 Tokio 异步运行时）都是完全由 AI（Cursor、Claude Code 和 OpenCode）生成的，没有任何手工编码。**

这个项目旨在证明最先进的 AI 代码生成可以架构、实现和优化超低级 Linux 内核基础设施以及复杂系统软件，匹配严格的生产性能指标。

---

## 💡 什么是 Rustagon?

**Rustagon** 是一个完全用 **Rust** 重写的容器运行时安全引擎，使用 [Aya](https://aya-rs.dev/) eBPF 框架作为 **CNCF Falco** 的替代品。

它为 Kubernetes 和 Linux 容器提供实时威胁检测、系统调用追踪和基于规则的审计——无需传统安全代理的遗留内存安全风险或沉重的 C++ 运行时开销。

### 核心使命：
1. **0% 手写代码**：完全通过 AI 提示、多代理审查和自主 AI 编码工作流构建。
2. **100% 纯 Rust 栈**：使用 **Rust** 构建用户空间逻辑和内核空间 eBPF 程序（通过 `aya` 和 `aya-ebpf`），零依赖传统 C++ 库（`libscap`/`libsinsp`）。
3. **100% Falco 测试套件兼容性**：设计用于通过所有官方 Falco 端对端（E2E）、规则引擎和 AST 语法测试套件。
4. **相等或更高的性能**：在高容量事件突发下达到并超过 Falco 的吞吐量和内存指标。

---

## 🏗️ 架构

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
                   |         eBPF Drivers（Aya Rust / eBPF）         |
                   |                                                 |
                   |  +------------------+     +------------------+  |
                   |  | Tracepoints /    |     |  bpf_lsm Hooks   |  |
                   |  | Raw Tracepoints  |     |  (Enforcement)   |  |
                   |  +------------------+     +------------------+  |
                   +-------------------------------------------------+
```

---

## 🎯 项目特性

### 性能与安全
- **零拷贝事件流**：通过 eBPF ringbuffer 进行高效的内核-用户空间通信
- **内存安全**：100% Rust 代码排除整类漏洞（缓冲区溢出、使用后释放等）
- **低延迟**：异步事件处理，无阻塞系统调用
- **可扩展性**：支持大规模容器环境的并发事件处理

### 架构特点
- **模块化设计**：清晰分离关注点（内核、用户空间、规则、解析）
- **纯 Rust 内核程序**：使用 `aya-ebpf` 而非 C 进行内核态编程
- **异步优先**：用户空间全面采用 Tokio 异步运行时
- **无锁并发**：优先使用无锁数据结构进行线程间通讯

---

## 📦 工作空间结构

```
Rustagon/
├── Cargo.toml                 # Workspace 配置
├── xtask/                     # Build 和 development 脚本
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── rustagon-common/           # 共享数据结构和事件定义
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── events.rs          # Event 定义
│       └── models.rs          # 共享数据结构
├── rustagon-ebpf/             # eBPF 内核程序
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── syscalls.rs        # 系统调用追踪
│       └── lsm.rs             # LSM hooks
├── rustagon-parser/           # Falco 规则和 AST 解析器
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── parser.rs          # YAML 解析
│       └── evaluator.rs       # AST 计算引擎
└── rustagon-core/             # 用户空间守护进程
    ├── Cargo.toml
    └── src/
        ├── main.rs
        ├── daemon.rs          # 主守护进程
        ├── ringbuf.rs         # RingBuffer 消费者
        └── runner.rs          # 规则执行引擎
```

---

## 🚀 快速开始

### 环境要求
- Rust 1.80+
- Linux 5.8+（eBPF 支持）
- LLVM 12+
- Clang

### 构建项目

```bash
# 编译所有 crates
cargo build --release

# 使用 xtask 编译 eBPF 程序
cargo xtask build-ebpf --release

# 运行 rustagon-core（需要 root 权限）
sudo cargo run --release -p rustagon-core
```

### 运行规则

```bash
# 使用默认 Falco 规则文件
sudo cargo run --release -p rustagon-core -- -r rules.yaml

# 启用调试日志
RUST_LOG=debug sudo cargo run --release -p rustagon-core
```

---

## 📋 约束规则和设计原则

### Rule 1: 禁止 C/C++ 依赖
- ❌ 不允许使用 `libbpf-sys`、`libscap`、`libsinsp` 等 C++ 库
- ✅ 必须使用 `aya`（用户空间）和 `aya-ebpf`（内核空间）
- ✅ 所有 syscall 追踪和内核交互都必须用 Rust eBPF 实现

### Rule 2: 异步优先设计
- ✅ 用户空间处理逻辑必须全部异步化（使用 `tokio`）
- ✅ 线程间通讯优先选择无锁队列（如 `crossbeam::queue`、`tokio::sync::mpsc`）
- ✅ 避免 mutex 和其他阻塞同步原语

### Rule 3: 内核-用户空间数据结构
- ✅ 所有共享数据结构必须标注 `#[repr(C)]`
- ✅ 内核态禁止动态内存分配（在 eBPF 中不支持）
- ✅ 使用固定大小的栈分配结构和数组

---

## 🔬 开发工作流

### 添加新的系统调用追踪

1. 在 `rustagon-common` 中定义事件结构：
```rust
#[repr(C)]
pub struct OpenEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub pathname: [u8; 256],
}
```

2. 在 `rustagon-ebpf` 中实现内核程序
3. 在 `rustagon-parser` 中添加规则支持
4. 在 `rustagon-core` 中实现事件处理

### 添加新规则

1. 编写 Falco YAML 规则文件
2. 使用 `rustagon-parser` 的 AST 评估器
3. 在规则引擎中集成新的条件

---

## 📚 相关资源

- [Aya eBPF Framework](https://aya-rs.dev/)
- [Falco Documentation](https://falco.org/)
- [Linux eBPF Syscall Tracing](https://www.kernel.org/doc/html/latest/userspace-api/ebpf/)
- [Rust Async Programming](https://rust-lang.github.io/async-book/)
- [Tokio Runtime](https://tokio.rs/)

---

## 📄 许可证

本项目采用 Apache License 2.0 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 🤝 贡献

由于本项目是 100% AI 生成的实验项目，我们欢迎：
- 🐛 Bug 报告和问题反馈
- 📝 文档改进
- 🧪 测试用例和性能基准
- 💡 架构设计建议

---

## ⚠️ 声明

本项目处于实验阶段。虽然所有代码都经过 AI 生成和优化，但在生产环境中使用前，请进行充分的测试和审查。

**Made with 💜 by AI • Steered by Humans**

