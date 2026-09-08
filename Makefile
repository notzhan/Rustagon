.PHONY: help build build-ebpf build-release test check clean fmt clippy

help:
	@echo "Rustagon Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make build           - Build debug binaries"
	@echo "  make build-release   - Build release binaries"
	@echo "  make build-ebpf      - Build eBPF programs"
	@echo "  make test            - Run all tests"
	@echo "  make check           - Check code without building"
	@echo "  make clippy          - Run clippy linter"
	@echo "  make fmt             - Format code"
	@echo "  make fmt-check       - Check code formatting"
	@echo "  make clean           - Remove build artifacts"

build:
	@echo "Building Rustagon (debug)..."
	cargo build

build-release:
	@echo "Building Rustagon (release)..."
	cargo build --release

build-ebpf:
	@echo "Building eBPF programs..."
	cargo xtask build-ebpf --release

test:
	@echo "Running tests..."
	cargo test --lib

check:
	@echo "Checking code..."
	cargo check --all-targets

clippy:
	@echo "Running clippy..."
	cargo clippy --all-targets -- -D warnings

fmt:
	@echo "Formatting code..."
	cargo fmt --all

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt --all -- --check

clean:
	@echo "Cleaning build artifacts..."
	cargo clean

audit:
	@echo "Checking for known vulnerabilities..."
	cargo audit
