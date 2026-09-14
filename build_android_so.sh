#!/usr/bin/env bash
set -euo pipefail

# Builds the future mobile shared-library runtime. This currently requires the
# mobile C ABI bind layer (StartOpenFluxClient/StopOpenFluxClient/OpenFluxStats)
# to be present in the repository. The mobile app expects libopenflux.so.

ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/27.0.12077973}"
OUTPUT_DIR="${OUTPUT_DIR:-output/android/arm64-v8a}"
LIBRARY_NAME="${LIBRARY_NAME:-libopenflux.so}"

mkdir -p "${OUTPUT_DIR}"

export GOARCH=arm64
export GOOS=android
export CGO_ENABLED=1
export CC="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang"
export CXX="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang++"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

go build \
  -buildmode=c-shared \
  -trimpath \
  -ldflags="-s -w -checklinkname=0" \
  -o "${OUTPUT_DIR}/${LIBRARY_NAME}" \
  .

file "${OUTPUT_DIR}/${LIBRARY_NAME}"
shasum -a 256 "${OUTPUT_DIR}/${LIBRARY_NAME}"
