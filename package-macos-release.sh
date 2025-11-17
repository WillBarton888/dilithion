#!/bin/bash
################################################################
#  DILITHION - PACKAGE macOS RELEASE
################################################################
#  This script packages the macOS binary release
################################################################

# Use VERSION from environment if set, otherwise default to v1.0.11
if [ -z "$VERSION" ]; then
    VERSION="v1.0.11"
fi
RELEASE_NAME="dilithion-testnet-${VERSION}-macos-x64"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DILITHION macOS RELEASE"
echo "================================================================"
echo ""
echo "Version: ${VERSION}"
echo "Package: ${RELEASE_NAME}.tar.gz"
echo ""

# Create release directory
echo "[1/4] Creating release directory..."
rm -rf "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}"

# Copy binaries (macOS executables)
echo "[2/4] Copying binaries..."
cp dilithion-node "${RELEASE_DIR}/"
cp check-wallet-balance "${RELEASE_DIR}/"
cp genesis_gen "${RELEASE_DIR}/"

# Make binaries executable
chmod +x "${RELEASE_DIR}/dilithion-node"
chmod +x "${RELEASE_DIR}/check-wallet-balance"
chmod +x "${RELEASE_DIR}/genesis_gen"

# Copy launcher scripts
echo "[3/4] Copying launcher scripts and documentation..."
cp start-mining.sh "${RELEASE_DIR}/"
cp setup-and-start.sh "${RELEASE_DIR}/"

# Make scripts executable
chmod +x "${RELEASE_DIR}/start-mining.sh"
chmod +x "${RELEASE_DIR}/setup-and-start.sh"

# Copy documentation
cp README-MAC.txt "${RELEASE_DIR}/README.txt"
cp TESTNET-GUIDE.md "${RELEASE_DIR}/TESTNET-GUIDE.md"

# Create the tar.gz archive
echo "[4/4] Creating tar.gz archive..."
cd releases
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}"
cd ..

# Show results
echo ""
echo "================================================================"
echo "  PACKAGING COMPLETE!"
echo "================================================================"
echo ""
echo "Release package created:"
echo "  releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Package contents:"
ls -lh "releases/${RELEASE_NAME}/"
echo ""
echo "Archive size:"
ls -lh "releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Ready to upload to GitHub release!"
echo ""
