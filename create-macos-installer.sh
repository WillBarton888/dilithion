#!/bin/bash
#########################################################
#  Create Self-Extracting Installer for macOS
#########################################################
#  This creates a .app bundle and DMG installer
#########################################################

set -e

VERSION="v1.0.0-testnet"
APP_NAME="Dilithion Testnet Installer"
INSTALLER_NAME="dilithion-testnet-${VERSION}-macos-installer.run"

echo ""
echo "================================================================"
echo "  DILITHION - Create macOS Self-Extracting Installer"
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
cp README-MAC.txt "$TEMP_DIR/README.txt"
cp LICENSE "$TEMP_DIR/"

# Make scripts executable
chmod +x "$TEMP_DIR"/*.sh
chmod +x "$TEMP_DIR"/dilithion-node
chmod +x "$TEMP_DIR"/check-wallet-balance
chmod +x "$TEMP_DIR"/genesis_gen

echo "Creating self-extracting installer..."

# Create the installer script
cat > "$INSTALLER_NAME" << 'INSTALLER_EOF'
#!/bin/bash
#########################################################
#  DILITHION TESTNET INSTALLER FOR macOS
#########################################################

EXTRACT_DIR="$HOME/dilithion-testnet"

# macOS-friendly dialog using osascript
show_dialog() {
    osascript -e "display dialog \"$1\" buttons {\"OK\"} default button \"OK\"" 2>/dev/null || echo "$1"
}

show_notification() {
    osascript -e "display notification \"$1\" with title \"Dilithion Installer\"" 2>/dev/null
}

echo ""
echo "================================================================"
echo "  DILITHION TESTNET INSTALLER FOR macOS"
echo "================================================================"
echo ""
echo "  This will extract Dilithion cryptocurrency testnet files."
echo ""
read -p "  Extract to directory [$EXTRACT_DIR]: " user_dir
if [ ! -z "$user_dir" ]; then
    EXTRACT_DIR="$user_dir"
fi

# Create extraction directory
mkdir -p "$EXTRACT_DIR"
cd "$EXTRACT_DIR"

echo ""
echo "  Extracting files to: $(pwd)"
echo ""

# Find the line number where the archive starts
ARCHIVE_LINE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' "$0")

# Extract the archive
tail -n+$ARCHIVE_LINE "$0" | tar xzf -

echo ""
echo "================================================================"
echo "  EXTRACTION COMPLETE!"
echo "================================================================"
echo ""
echo "  Files extracted to: $(pwd)"
echo ""
echo "  Next steps:"
echo "    cd $EXTRACT_DIR"
echo "    ./setup-and-start.sh    # Interactive setup wizard"
echo "    ./start-mining.sh       # Quick start mining"
echo ""
echo "  IMPORTANT FOR macOS:"
echo "    If you see 'cannot be opened because the developer"
echo "    cannot be verified', go to System Preferences > Security"
echo "    & Privacy and click 'Allow Anyway'"
echo ""
echo "  View README.txt for detailed instructions."
echo ""

# Show notification
show_notification "Installation complete! Files extracted to: $EXTRACT_DIR"

# Ask if user wants to view README
read -p "  View README now? (y/n): " view_readme
if [ "$view_readme" = "y" ] || [ "$view_readme" = "Y" ]; then
    # Use macOS default text viewer
    open -t README.txt 2>/dev/null || less README.txt || cat README.txt
fi

# Ask if user wants to run setup wizard
echo ""
read -p "  Run setup wizard now? (y/n): " run_setup
if [ "$run_setup" = "y" ] || [ "$run_setup" = "Y" ]; then
    ./setup-and-start.sh
fi

exit 0

__ARCHIVE_BELOW__
INSTALLER_EOF

# Append the tar archive to the installer script
tar czf - -C "$TEMP_DIR" . >> "$INSTALLER_NAME"

# Make installer executable
chmod +x "$INSTALLER_NAME"

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "================================================================"
echo "  SUCCESS!"
echo "================================================================"
echo ""
echo "  Created: $INSTALLER_NAME"
echo ""
ls -lh "$INSTALLER_NAME" 2>/dev/null || stat -f "%N %z bytes" "$INSTALLER_NAME"
echo ""
echo "  Users can now:"
echo "    1. Download the .run file"
echo "    2. Run: chmod +x $INSTALLER_NAME"
echo "    3. Run: ./$INSTALLER_NAME"
echo "    4. Files will auto-extract and install"
echo ""
echo "  Note: macOS users may need to allow the app in"
echo "  System Preferences > Security & Privacy"
echo ""
echo "  Upload this to GitHub Releases!"
echo ""
