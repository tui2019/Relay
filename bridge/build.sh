#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

ARCH_FLAGS=()
if [ "${1:-}" = "--universal" ]; then
  ARCH_FLAGS=(-arch arm64 -arch x86_64)
fi

clang -O2 -fobjc-arc -Wall -Wextra \
  ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} \
  -framework Foundation \
  -framework CoreBluetooth \
  -framework CoreWLAN \
  -framework Network \
  -framework AppKit \
  RelayBridge.m \
  -o RelayBridge
echo "Built $(pwd)/RelayBridge"
