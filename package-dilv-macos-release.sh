#!/bin/bash
################################################################
#  DILV - PACKAGE macOS RELEASE
################################################################
#  Packages the dilv-node macOS binary release
################################################################

if [ -z "$VERSION" ]; then
    VERSION="v1.0.0"
fi
RELEASE_NAME="dilv-${VERSION}-mainnet-macos-x64"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DilV macOS RELEASE"
echo "================================================================"
echo ""
echo "Version: ${VERSION}"
echo "Package: ${RELEASE_NAME}.tar.gz"
echo ""

# Create release directory
echo "[1/4] Creating release directory..."
rm -rf "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}"

# Copy binaries
echo "[2/4] Copying binaries..."
cp dilv-node "${RELEASE_DIR}/" || { echo "ERROR: dilv-node not found. Run 'make dilv-node' first."; exit 1; }
cp check-wallet-balance "${RELEASE_DIR}/" || { echo "ERROR: check-wallet-balance not found."; exit 1; }

chmod +x "${RELEASE_DIR}/dilv-node"
chmod +x "${RELEASE_DIR}/check-wallet-balance"

# Copy launcher scripts and documentation
echo "[3/4] Copying launcher scripts and documentation..."
cp start-dilv-mining.sh "${RELEASE_DIR}/" || { echo "ERROR: start-dilv-mining.sh not found."; exit 1; }
cp setup-dilv.sh "${RELEASE_DIR}/" || { echo "ERROR: setup-dilv.sh not found."; exit 1; }
chmod +x "${RELEASE_DIR}/start-dilv-mining.sh"
chmod +x "${RELEASE_DIR}/setup-dilv.sh"
cp README-DILV-MAC.txt "${RELEASE_DIR}/README.txt" || { echo "ERROR: README-DILV-MAC.txt not found."; exit 1; }

# Create archive
echo "[4/4] Creating tar.gz archive..."
cd releases
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}"
cd ..

echo ""
echo "================================================================"
echo "  PACKAGING COMPLETE!"
echo "================================================================"
echo ""
echo "Release package: releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Package contents:"
ls -lh "releases/${RELEASE_NAME}/"
echo ""
echo "Archive size:"
ls -lh "releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Ready to upload to GitHub release!"
echo ""
