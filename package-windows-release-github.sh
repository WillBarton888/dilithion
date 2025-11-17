#!/bin/bash
################################################################
#  DILITHION - PACKAGE WINDOWS RELEASE FOR GITHUB ACTIONS
################################################################
#  This script packages Windows binaries built by GitHub Actions
################################################################

# Use VERSION from environment if set, otherwise default to v1.0.11
if [ -z "$VERSION" ]; then
    VERSION="v1.0.11"
fi
RELEASE_NAME="dilithion-testnet-${VERSION}-windows-x64"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DILITHION WINDOWS RELEASE"
echo "================================================================"
echo ""
echo "Version: ${VERSION}"
echo "Package: ${RELEASE_NAME}.zip"
echo ""

# Create release directory
echo "[1/5] Creating release directory..."
rm -rf "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}"

# Copy binaries (from build directory)
echo "[2/5] Copying binaries and wallet tools..."
cp dilithion-node.exe "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy dilithion-node.exe"; exit 1; }
cp check-wallet-balance.exe "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy check-wallet-balance.exe"; exit 1; }
cp genesis_gen.exe "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy genesis_gen.exe"; exit 1; }
cp dilithion-wallet.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy dilithion-wallet.bat"; exit 1; }

# Copy required DLLs from MSYS2
echo "[3/5] Copying runtime libraries (DLLs)..."
cp /mingw64/bin/libwinpthread-1.dll "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy libwinpthread-1.dll"; exit 1; }
cp /mingw64/bin/libgcc_s_seh-1.dll "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy libgcc_s_seh-1.dll"; exit 1; }
cp /mingw64/bin/libstdc++-6.dll "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy libstdc++-6.dll"; exit 1; }
cp /mingw64/bin/libleveldb.dll "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy libleveldb.dll"; exit 1; }
cp /mingw64/bin/libcrypto-3-x64.dll "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy libcrypto-3-x64.dll"; exit 1; }
cp /mingw64/bin/libssl-3-x64.dll "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy libssl-3-x64.dll"; exit 1; }
echo "   [SUCCESS] All 6 DLLs copied successfully"

# Copy launcher scripts and documentation
echo "[4/5] Copying launcher scripts and documentation..."
cp SETUP-AND-START.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy SETUP-AND-START.bat"; exit 1; }
cp START-MINING.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy START-MINING.bat"; exit 1; }
cp SETUP-AND-START-NO-COLOR.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy SETUP-AND-START-NO-COLOR.bat"; exit 1; }
cp TEST-DEBUG.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy TEST-DEBUG.bat"; exit 1; }
cp ULTRA-DEBUG.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy ULTRA-DEBUG.bat"; exit 1; }
cp FIX-WINDOWS-DEFENDER.bat "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy FIX-WINDOWS-DEFENDER.bat"; exit 1; }
cp README-WINDOWS.txt "${RELEASE_DIR}/README.txt" || { echo "ERROR: Failed to copy README-WINDOWS.txt"; exit 1; }
cp TESTNET-GUIDE.md "${RELEASE_DIR}/TESTNET-GUIDE.md" || { echo "ERROR: Failed to copy TESTNET-GUIDE.md"; exit 1; }
cp ANTIVIRUS-SOLUTION.md "${RELEASE_DIR}/" || { echo "ERROR: Failed to copy ANTIVIRUS-SOLUTION.md"; exit 1; }
echo "   All scripts and documentation copied successfully"

# Create the ZIP archive
echo "[5/5] Creating ZIP archive..."
cd releases
powershell.exe -Command "Compress-Archive -Path '${RELEASE_NAME}/*' -DestinationPath '${RELEASE_NAME}.zip' -Force"
cd ..

# Show results
echo ""
echo "================================================================"
echo "  PACKAGING COMPLETE!"
echo "================================================================"
echo ""
echo "Release package created:"
echo "  releases/${RELEASE_NAME}.zip"
echo ""
echo "Package contents:"
ls -lh "releases/${RELEASE_NAME}/"
echo ""
echo "Archive size:"
ls -lh "releases/${RELEASE_NAME}.zip"
echo ""
echo "Ready to upload to GitHub release!"
echo ""
