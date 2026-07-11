#!/usr/bin/env bash
set -euo pipefail

ZIG="${ZIG:-zig}"
ZIG_TARGET="${ZIG_TARGET:-x86_64-linux-musl}"
BUILD_DIR="${BUILD_DIR:-build-musl}"
BUILD_TYPE="${BUILD_TYPE:-Release}"

export CC="${ZIG} cc -target ${ZIG_TARGET}"
export CXX="${ZIG} c++ -target ${ZIG_TARGET}"

CMAKE_ARGS=(-DCMAKE_BUILD_TYPE="${BUILD_TYPE}" -DCMAKE_EXE_LINKER_FLAGS="-static")
if [ -n "${X86TESTER_VERSION:-}" ]; then
  CMAKE_ARGS+=("-DX86TESTER_VERSION=${X86TESTER_VERSION}")
fi

cmake -S . -B "${BUILD_DIR}" -G Ninja "${CMAKE_ARGS[@]}"

cmake --build "${BUILD_DIR}" --target x86Tester-cli
