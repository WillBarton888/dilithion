#!/bin/bash
#########################################################
#  Create SECURE Self-Extracting Installer for Linux
#########################################################
#  Security improvements:
#  - Path sanitization
#  - Input validation
#  - Error handling
#  - Hash verification
#########################################################

set -e

VERSION="v1.0.0-testnet"
INSTALLER_NAME="dilithion-testnet-${VERSION}-linux-x64-installer.run"

echo ""
echo "================================================================"
echo "  DILITHION - Create Linux Self-Extracting Installer (SECURE)"
echo "================================================================"
echo ""

# Create temporary directory
TEMP_DIR="temp_installer"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

echo "Copying files to package..."

# Copy binaries
cp dilithion-node "$TEMP_DIR/"
cp check-wallet-balance "$TEMP_DIR/"
cp genesis_gen "$TEMP_DIR/"

# Copy scripts
cp start-mining.sh "$TEMP_DIR/"
cp setup-and-start.sh "$TEMP_DIR/"

# Copy documentation
cp README-LINUX.txt "$TEMP_DIR/README.txt"
cp LICENSE "$TEMP_DIR/"

# Make scripts executable
chmod +x "$TEMP_DIR"/*.sh
chmod +x "$TEMP_DIR"/dilithion-node
chmod +x "$TEMP_DIR"/check-wallet-balance
chmod +x "$TEMP_DIR"/genesis_gen

echo "Creating self-extracting installer with security checks..."

# Create the installer script
cat > "$INSTALLER_NAME" << 'INSTALLER_EOF'
#!/bin/bash
#########################################################
#  DILITHION TESTNET INSTALLER (SECURE VERSION)
#########################################################

set -e  # Exit on error

# Default extraction directory
DEFAULT_DIR="dilithion-testnet"
EXTRACT_DIR="$DEFAULT_DIR"

echo ""
echo "================================================================"
echo "  DILITHION TESTNET INSTALLER"
echo "================================================================"
echo ""
echo "  This will extract Dilithion cryptocurrency testnet files."
echo ""

# Function to sanitize and validate path
sanitize_path() {
    local input_path="$1"

    # Remove leading/trailing whitespace
    input_path=$(echo "$input_path" | xargs)

    # Check for empty input
    if [ -z "$input_path" ]; then
        echo "$DEFAULT_DIR"
        return 0
    fi

    # Reject paths with dangerous characters
    if [[ "$input_path" =~ [\;\|\&\$\`] ]]; then
        echo "ERROR: Path contains dangerous characters" >&2
        return 1
    fi

    # Reject absolute paths outside of home and current directory
    if [[ "$input_path" == /* ]] && [[ "$input_path" != "$HOME"* ]] && [[ "$input_path" != /tmp/* ]]; then
        echo "ERROR: Absolute paths outside \$HOME are not allowed" >&2
        return 1
    fi

    # Reject path traversal attempts
    if [[ "$input_path" =~ \.\. ]]; then
        echo "ERROR: Path traversal (..) is not allowed" >&2
        return 1
    fi

    # Convert to absolute path safely
    if [[ "$input_path" == /* ]]; then
        echo "$input_path"
    else
        echo "$(pwd)/$input_path"
    fi

    return 0
}

# Get user input with validation
while true; do
    read -p "  Extract to directory [$DEFAULT_DIR]: " user_dir

    # Use default if empty
    if [ -z "$user_dir" ]; then
        EXTRACT_DIR="$DEFAULT_DIR"
        break
    fi

    # Sanitize and validate
    if EXTRACT_DIR=$(sanitize_path "$user_dir"); then
        break
    else
        echo "  Invalid directory. Please try again."
        echo ""
    fi
done

echo ""
echo "  Extracting files to: $EXTRACT_DIR"
echo ""

# Create extraction directory with error handling
if ! mkdir -p "$EXTRACT_DIR" 2>/dev/null; then
    echo "ERROR: Failed to create directory: $EXTRACT_DIR" >&2
    echo "       Please check permissions and try again." >&2
    exit 1
fi

# Change to extraction directory
if ! cd "$EXTRACT_DIR" 2>/dev/null; then
    echo "ERROR: Failed to access directory: $EXTRACT_DIR" >&2
    exit 1
fi

echo "  Extraction directory: $(pwd)"
echo ""

# Find the line number where the archive starts
ARCHIVE_LINE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' "$0")

if [ -z "$ARCHIVE_LINE" ]; then
    echo "ERROR: Installer archive not found!" >&2
    exit 1
fi

# Extract the archive with error handling
echo "  Extracting archive..."
if ! tail -n+$ARCHIVE_LINE "$0" | tar xzf - 2>/dev/null; then
    echo "ERROR: Archive extraction failed!" >&2
    echo "       The installer may be corrupted." >&2
    exit 1
fi

# Verify extraction
if [ ! -f "dilithion-node" ] || [ ! -f "README.txt" ]; then
    echo "ERROR: Extraction incomplete! Required files missing." >&2
    exit 1
fi

echo ""
echo "================================================================"
echo "  EXTRACTION COMPLETE!"
echo "================================================================"
echo ""
echo "  Files extracted to: $(pwd)"
echo ""
echo "  Contents:"
ls -lh dilithion-node check-wallet-balance genesis_gen *.sh 2>/dev/null | awk '{print "    " $9 " (" $5 ")"}'
echo ""
echo "  Next steps:"
echo "    cd $EXTRACT_DIR"
echo "    ./setup-and-start.sh    # Interactive setup wizard"
echo "    ./start-mining.sh       # Quick start mining"
echo ""
echo "  View README.txt for detailed instructions."
echo ""

# Ask if user wants to view README
read -p "  View README now? (y/n): " view_readme
if [ "$view_readme" = "y" ] || [ "$view_readme" = "Y" ]; then
    less README.txt 2>/dev/null || more README.txt 2>/dev/null || cat README.txt
fi

echo ""
echo "  Installation complete! Happy mining!"
echo ""

exit 0

__ARCHIVE_BELOW__
INSTALLER_EOF

# Append the tar archive to the installer script
tar czf - -C "$TEMP_DIR" . >> "$INSTALLER_NAME"

# Make installer executable
chmod +x "$INSTALLER_NAME"

# Generate checksum
sha256sum "$INSTALLER_NAME" > "$INSTALLER_NAME.sha256"

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "================================================================"
echo "  SUCCESS! SECURE INSTALLER CREATED"
echo "================================================================"
echo ""
echo "  Created: $INSTALLER_NAME"
echo ""
ls -lh "$INSTALLER_NAME"
echo ""
echo "  SHA256 Checksum:"
cat "$INSTALLER_NAME.sha256"
echo ""
echo "  Security features:"
echo "    ✓ Path injection protection"
echo "    ✓ Input validation"
echo "    ✓ Directory traversal prevention"
echo "    ✓ Absolute path restrictions"
echo "    ✓ Extraction verification"
echo "    ✓ Error handling"
echo "    ✓ SHA256 checksum"
echo ""
echo "  Users can now:"
echo "    1. Download the .run file"
echo "    2. Verify: sha256sum -c $INSTALLER_NAME.sha256"
echo "    3. Run: chmod +x $INSTALLER_NAME"
echo "    4. Run: ./$INSTALLER_NAME"
echo ""
echo "  Upload both files to GitHub Releases!"
echo ""
