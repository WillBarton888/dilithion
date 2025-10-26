#!/bin/bash
# Dilithion Release Build Script
# Builds release binaries for all platforms after genesis block is mined
# Usage: ./build-release.sh v1.0.0

set -e  # Exit on error

VERSION="${1:-v1.0.0}"
BUILD_DIR="build/release-$VERSION"
RELEASE_DIR="releases/$VERSION"

echo "========================================"
echo "Dilithion Release Build"
echo "Version: $VERSION"
echo "========================================"
echo ""

# Check that genesis block has been mined
echo "[1/7] Verifying genesis block..."
GENESIS_NONCE=$(grep "const uint32_t NONCE" src/node/genesis.h | awk '{print $5}' | tr -d ';')
if [ "$GENESIS_NONCE" = "0" ]; then
    echo "ERROR: Genesis block not mined yet (NONCE = 0)"
    echo "Please mine genesis block first with: ./genesis_gen --mine"
    exit 1
fi
echo "✓ Genesis nonce found: $GENESIS_NONCE"
echo ""

# Clean previous builds
echo "[2/7] Cleaning previous builds..."
rm -rf "$BUILD_DIR"
rm -rf "$RELEASE_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$RELEASE_DIR"
echo "✓ Build directories ready"
echo ""

# Build dependencies
echo "[3/7] Building dependencies..."
echo "Building RandomX..."
cd depends/randomx
if [ -d "build" ]; then
    rm -rf build
fi
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
cd ../../..
echo "✓ RandomX built"

echo "Building Dilithium..."
cd depends/dilithium/ref
make clean
make -j$(nproc)
cd ../../..
echo "✓ Dilithium built"
echo ""

# Build Dilithion binaries
echo "[4/7] Building Dilithion binaries..."
make clean
make CXXFLAGS="-O3 -march=native -DNDEBUG" dilithion-node
make CXXFLAGS="-O3 -march=native -DNDEBUG" genesis_gen
echo "✓ Binaries built"
echo ""

# Verify binaries work
echo "[5/7] Verifying binaries..."
./dilithion-node --version || echo "Warning: --version not implemented"
./genesis_gen
echo "✓ Binaries verified"
echo ""

# Create release packages
echo "[6/7] Creating release packages..."

# Detect platform
PLATFORM=$(uname -s)
ARCH=$(uname -m)

case "$PLATFORM" in
    Linux)
        PLATFORM_NAME="linux"
        ;;
    Darwin)
        PLATFORM_NAME="macos"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        PLATFORM_NAME="windows"
        ;;
    *)
        PLATFORM_NAME="unknown"
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="x64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    *)
        ARCH_NAME="$ARCH"
        ;;
esac

RELEASE_NAME="dilithion-$VERSION-$PLATFORM_NAME-$ARCH_NAME"
PACKAGE_DIR="$BUILD_DIR/$RELEASE_NAME"

echo "Creating package: $RELEASE_NAME"
mkdir -p "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR/bin"
mkdir -p "$PACKAGE_DIR/docs"

# Copy binaries
cp dilithion-node "$PACKAGE_DIR/bin/"
cp genesis_gen "$PACKAGE_DIR/bin/"

# Copy documentation
cp README.md "$PACKAGE_DIR/"
cp LICENSE "$PACKAGE_DIR/"
cp SECURITY.md "$PACKAGE_DIR/"
cp TEAM.md "$PACKAGE_DIR/"
cp CONTRIBUTING.md "$PACKAGE_DIR/"
cp WHITEPAPER.md "$PACKAGE_DIR/docs/"

# Create archive
cd "$BUILD_DIR"
if [ "$PLATFORM_NAME" = "windows" ]; then
    zip -r "$RELEASE_NAME.zip" "$RELEASE_NAME"
    mv "$RELEASE_NAME.zip" "../../$RELEASE_DIR/"
    echo "✓ Created $RELEASE_NAME.zip"
else
    tar -czf "$RELEASE_NAME.tar.gz" "$RELEASE_NAME"
    mv "$RELEASE_NAME.tar.gz" "../../$RELEASE_DIR/"
    echo "✓ Created $RELEASE_NAME.tar.gz"
fi
cd ../..
echo ""

# Generate checksums
echo "[7/7] Generating checksums..."
cd "$RELEASE_DIR"
if command -v sha256sum &> /dev/null; then
    sha256sum * > SHA256SUMS
elif command -v shasum &> /dev/null; then
    shasum -a 256 * > SHA256SUMS
fi
cd ../..
echo "✓ Checksums generated"
echo ""

echo "========================================"
echo "Release Build Complete!"
echo "========================================"
echo ""
echo "Release package: $RELEASE_DIR/$RELEASE_NAME.*"
echo ""
echo "Next steps:"
echo "1. Test the release package on a clean system"
echo "2. Create GitHub release with tag: $VERSION"
echo "3. Upload package to GitHub releases"
echo "4. Update website download links"
echo ""
