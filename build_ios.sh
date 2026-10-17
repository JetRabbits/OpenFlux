#!/bin/bash
set -e

OUTPUT_DIR="output/ios"
LIBRARY_NAME="liboflux"
# Paths are this checkout's, whatever the caller's directory: an app that
# links the core as a submodule runs core/build_ios.sh from its own root.
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/$OUTPUT_DIR/$LIBRARY_NAME.a"

# Paths configuration
XCODE_PATH="${XCODE_PATH:-$(xcode-select -p 2>/dev/null | sed 's#/Contents/Developer##')}"
if [ -z "$XCODE_PATH" ] || [ ! -d "$XCODE_PATH" ]; then
    XCODE_PATH="/Applications/Xcode.app"
fi
DEVELOPER_DIR="$XCODE_PATH/Contents/Developer"
SDK_PATH="$DEVELOPER_DIR/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk"
CLANG="$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"

mkdir -p "$ROOT/$OUTPUT_DIR"

# Verify paths
if [ ! -d "$SDK_PATH" ]; then
    echo "SDK not found: $SDK_PATH"
    exit 1
fi

if [ ! -f "$CLANG" ]; then
    echo "Compiler not found: $CLANG"
    exit 1
fi

# Build environment
export GOARCH=arm64
export GOOS=ios
export CGO_ENABLED=1
export SDK_PATH="$SDK_PATH"
export CC="$CLANG -isysroot $SDK_PATH -arch arm64 -miphoneos-version-min=13.0"
export CXX="${CLANG}++ -isysroot $SDK_PATH -arch arm64 -miphoneos-version-min=13.0"
export CGO_CFLAGS="-isysroot $SDK_PATH -arch arm64 -miphoneos-version-min=13.0"
export CGO_LDFLAGS="-isysroot $SDK_PATH -arch arm64 -miphoneos-version-min=13.0"

echo "Building for iOS (arm64)..."

# Build static library
# Fork: the iOS C API is the root package's //export surface (export_ios*.go,
# bind_mobile.go) — the surface the JetRabbits mobile pipeline links against.
if go build \
    -buildmode=c-archive \
    -ldflags="-s -w" \
    -trimpath \
    -o "$OUT" \
    . ; then
    
    # go build -buildmode=c-archive auto-generates $OUT.h next to the .a
    # from the //export comments in bind_mobile.go — no manual header stub.
    echo "Build complete: $OUT"
    ls -lh "$OUT"
    
else
    echo "Build failed"
    exit 1
fi
