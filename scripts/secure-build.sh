#!/usr/bin/env bash
# Secure Build with Hardening
set -e

BUILD_TYPE="${1:-Debug}"
BUILD_DIR="build-secure"

echo "========================================="
echo "Dilithion Secure Build"
echo "========================================="

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Security hardening flags
export CXXFLAGS="-fstack-protector-all -fPIE -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security"
export LDFLAGS="-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"

# Add sanitizers for Debug builds
if [ "$BUILD_TYPE" = "Debug" ]; then
    export CXXFLAGS="$CXXFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
    export LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
fi

echo "Building with security hardening..."
cmake .. \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS"

cmake --build . -- -j$(nproc)

echo "✓ Secure build complete"
