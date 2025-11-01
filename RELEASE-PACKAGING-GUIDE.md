# Dilithion Release Packaging Guide

This guide explains how to build, package, and release Dilithion binaries for all platforms.

## Overview

We provide three release packages:
- **Windows**: `dilithion-testnet-v1.0.0-windows-x64.zip`
- **Linux**: `dilithion-testnet-v1.0.0-linux-x64.tar.gz`
- **macOS**: `dilithion-testnet-v1.0.0-macos-x64.tar.gz`

Each package includes:
- All binaries (dilithion-node, check-wallet-balance, genesis_gen)
- One-click launcher scripts
- Interactive setup wizards
- Platform-specific README
- Testnet setup guide

## Prerequisites

### For Windows Builds
- Windows 10/11
- MinGW-w64 or Visual Studio Build Tools
- Git Bash (for running packaging script)

### For Linux Builds
- Linux (Ubuntu 20.04+ or similar)
- GCC 8+ or Clang 10+
- Make, Git
- Standard build tools

### For macOS Builds
- macOS 10.13+
- Xcode Command Line Tools
- Homebrew (optional, for dependencies)

## Step 1: Build Binaries

### Windows Build

```batch
# Install MinGW-w64 if not already installed
# Download from: https://www.mingw-w64.org/

# Open Command Prompt in the dilithion directory
cd C:\path\to\dilithion

# Clean previous builds
make clean

# Build with MinGW
mingw32-make

# Or with MSVC (if using Visual Studio)
nmake
```

Expected output:
- `dilithion-node.exe` (main node)
- `check-wallet-balance.exe` (balance checker)
- `genesis_gen.exe` (genesis generator)

### Linux Build

```bash
cd /path/to/dilithion

# Clean previous builds
make clean

# Build
make

# Verify binaries
ls -lh dilithion-node check-wallet-balance genesis_gen
```

### macOS Build

```bash
cd /path/to/dilithion

# Clean previous builds
make clean

# Build
make

# Verify binaries
ls -lh dilithion-node check-wallet-balance genesis_gen

# Optional: Sign binaries for Gatekeeper
# (Requires Apple Developer account)
codesign -s "Developer ID Application: Your Name" dilithion-node
codesign -s "Developer ID Application: Your Name" check-wallet-balance
codesign -s "Developer ID Application: Your Name" genesis_gen
```

## Step 2: Package Releases

### Windows Packaging

```batch
# Run the Windows packaging script
package-windows-release.bat
```

This creates: `releases/dilithion-testnet-v1.0.0-windows-x64.zip`

### Linux Packaging

```bash
# Run the Linux packaging script
./package-linux-release.sh
```

This creates: `releases/dilithion-testnet-v1.0.0-linux-x64.tar.gz`

### macOS Packaging

```bash
# Run the macOS packaging script
./package-macos-release.sh
```

This creates: `releases/dilithion-testnet-v1.0.0-macos-x64.tar.gz`

## Step 3: Test Packages

Before uploading, test each package on the target platform:

### Windows Test

1. Extract the ZIP file
2. Double-click `START-MINING.bat`
3. Verify it connects to seed node and starts mining
4. Press Ctrl+C to stop
5. Test `SETUP-AND-START.bat` wizard
6. Test `check-wallet-balance.exe`

### Linux Test

1. Extract the tar.gz file:
   ```bash
   tar -xzf dilithion-testnet-v1.0.0-linux-x64.tar.gz
   cd dilithion-testnet-v1.0.0-linux-x64
   ```

2. Test one-click launcher:
   ```bash
   ./start-mining.sh
   ```

3. Stop with Ctrl+C

4. Test interactive wizard:
   ```bash
   ./setup-and-start.sh
   ```

5. Test balance checker:
   ```bash
   ./check-wallet-balance
   ```

### macOS Test

Same as Linux, but also verify Gatekeeper behavior:

1. Right-click `dilithion-node` → Open
2. Click "Open" in security dialog
3. Verify it runs without "unidentified developer" errors

## Step 4: Upload to GitHub Release

### Method 1: Using GitHub CLI (Recommended)

```bash
# Create a new release (if not exists)
gh release create v1.0.0-testnet \
  --title "Dilithion Testnet v1.0.0" \
  --notes "See RELEASE-NOTES.md for details"

# Upload all release packages
gh release upload v1.0.0-testnet \
  releases/dilithion-testnet-v1.0.0-windows-x64.zip \
  releases/dilithion-testnet-v1.0.0-linux-x64.tar.gz \
  releases/dilithion-testnet-v1.0.0-macos-x64.tar.gz
```

### Method 2: Using GitHub Web Interface

1. Go to: https://github.com/WillBarton888/dilithion/releases
2. Click "Draft a new release"
3. Tag: `v1.0.0-testnet`
4. Title: `Dilithion Testnet v1.0.0`
5. Description: Paste from `RELEASE-NOTES.md`
6. Upload the three release packages:
   - `dilithion-testnet-v1.0.0-windows-x64.zip`
   - `dilithion-testnet-v1.0.0-linux-x64.tar.gz`
   - `dilithion-testnet-v1.0.0-macos-x64.tar.gz`
7. Check "This is a pre-release" (for testnet)
8. Click "Publish release"

## Step 5: Update Website

After uploading to GitHub, update the website download links:

Edit `website/index.html`:

```html
<!-- Windows Download -->
<a href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0-testnet/dilithion-testnet-v1.0.0-windows-x64.zip" class="btn btn-download">
  Download for Windows (.zip)
</a>

<!-- Linux Download -->
<a href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0-testnet/dilithion-testnet-v1.0.0-linux-x64.tar.gz" class="btn btn-download">
  Download for Linux (.tar.gz)
</a>

<!-- macOS Download -->
<a href="https://github.com/WillBarton888/dilithion/releases/download/v1.0.0-testnet/dilithion-testnet-v1.0.0-macos-x64.tar.gz" class="btn btn-download">
  Download for macOS (.tar.gz)
</a>
```

Commit and push the website changes.

## Release Checklist

Before publishing a release, verify:

- [ ] All three platforms built successfully
- [ ] All packages created and tested on target platforms
- [ ] README files included in each package
- [ ] Launcher scripts work correctly
- [ ] Binaries connect to seed node
- [ ] Balance checker works
- [ ] TESTNET-GUIDE.md included
- [ ] Release notes written
- [ ] Version numbers consistent across all files
- [ ] GitHub release created with proper tags
- [ ] Website updated with download links
- [ ] Announcement prepared for social media

## Package Contents Verification

Each package should contain exactly these files:

### Windows Package
```
dilithion-testnet-v1.0.0-windows-x64/
├── dilithion-node.exe
├── check-wallet-balance.exe
├── genesis_gen.exe
├── START-MINING.bat
├── SETUP-AND-START.bat
├── README.txt (Windows-specific)
└── TESTNET-GUIDE.md
```

### Linux Package
```
dilithion-testnet-v1.0.0-linux-x64/
├── dilithion-node
├── check-wallet-balance
├── genesis_gen
├── start-mining.sh
├── setup-and-start.sh
├── README.txt (Linux-specific)
└── TESTNET-GUIDE.md
```

### macOS Package
```
dilithion-testnet-v1.0.0-macos-x64/
├── dilithion-node
├── check-wallet-balance
├── genesis_gen
├── start-mining.sh
├── setup-and-start.sh
├── README.txt (macOS-specific)
└── TESTNET-GUIDE.md
```

## Troubleshooting

### Windows Build Issues

**Problem**: `make: command not found`
**Solution**: Install MinGW-w64 and add to PATH

**Problem**: Missing DLLs when running
**Solution**: Statically link with `-static` flag in Makefile

### Linux Build Issues

**Problem**: Missing OpenSSL headers
**Solution**: `sudo apt-get install libssl-dev`

**Problem**: Permission denied
**Solution**: `chmod +x dilithion-node`

### macOS Build Issues

**Problem**: "Command Line Tools not found"
**Solution**: `xcode-select --install`

**Problem**: Gatekeeper blocks binary
**Solution**: Sign with Apple Developer certificate or instruct users to right-click → Open

### Packaging Issues

**Problem**: Windows packaging script fails
**Solution**: Run from Git Bash or ensure PowerShell is available

**Problem**: Line ending issues with bash scripts
**Solution**: Run `sed -i 's/\r$//' *.sh` to convert CRLF to LF

## Automated Release Process (Future)

Consider setting up GitHub Actions to automate builds:

```yaml
# .github/workflows/release.yml
name: Build and Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-windows:
    runs-on: windows-latest
    # ... build steps

  build-linux:
    runs-on: ubuntu-latest
    # ... build steps

  build-macos:
    runs-on: macos-latest
    # ... build steps

  release:
    needs: [build-windows, build-linux, build-macos]
    # ... upload all artifacts to release
```

## Version Numbering

Follow semantic versioning:
- **Major**: Breaking changes (e.g., 2.0.0)
- **Minor**: New features (e.g., 1.1.0)
- **Patch**: Bug fixes (e.g., 1.0.1)

For testnet releases, use suffix: `v1.0.0-testnet`
For mainnet releases, use: `v1.0.0`

## Contact

For build/release issues:
- GitHub: https://github.com/WillBarton888/dilithion/issues
- Website: https://dilithion.org
