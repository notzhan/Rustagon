#!/usr/bin/env bash
set -euo pipefail
FORBIDDEN='libbpf-sys|libscap|libsinsp|falcosecurity-libs|bpf-sys'
if cargo metadata --format-version 1 --no-deps >/dev/null 2>&1; then
  if cargo tree 2>/dev/null | rg -i "$FORBIDDEN"; then
    echo "FORBIDDEN dependency detected" >&2
    exit 1
  fi
fi
echo "dependency audit OK"
