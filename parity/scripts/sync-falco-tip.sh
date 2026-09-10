#!/usr/bin/env bash
set -euo pipefail
FALCO_PATH="${FALCO_PATH:-/nvraid1tank1/work/code/falco}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
commit=$(git -C "$FALCO_PATH" rev-parse HEAD)
describe=$(git -C "$FALCO_PATH" describe --tags --always)
{
  echo "commit=$commit"
  echo "describe=$describe"
  echo "engine_version=$(rg -n 'FALCO_ENGINE_VERSION_MINOR' "$FALCO_PATH/userspace/engine/falco_engine_version.h" | head -1)"
  echo "libs_version=see falco cmake pin"
  echo "path=$FALCO_PATH"
  echo "synced_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$ROOT/FALCO_TIP"
echo "Updated $ROOT/FALCO_TIP -> $commit"
