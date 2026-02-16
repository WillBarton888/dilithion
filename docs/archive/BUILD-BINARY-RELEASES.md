# How to Build and Release Binary Packages

## Overview

This guide explains how to create pre-compiled binary releases for Windows, Linux, and macOS, then upload them to GitHub for one-click downloads.

---

## Why Binary Releases?

**Current**: Users download source code and must compile with `make`
**Problem**: Most users don't have C++ compilers or build tools installed
**Solution**: Provide pre-built binaries they can download and run immediately

---

## What to Build

### For Each Platform:

**Windows** (`dilithion-windows-x64.zip`):
- `dilithion-node.exe`
- `dilithion-cli.exe`
- `genesis_gen.exe`
- `README.txt`
- Required DLLs (if any)

**Linux** (`dilithion-linux-x64.tar.gz`):
- `dilithion-node`
- `dilithion-cli`
- `genesis_gen`
- `README.txt`

**macOS** (`dilithion-macos-universal.zip`):
- `dilithion-node`
- `dilithion-cli`
- `genesis_gen`
- `README.txt`

---

## Building Binary Releases

### Option 1: Local Build (Current Machine)

#### Windows (WSL or MinGW):
```bash
# Clean build
make clean
make

# Create release directory
mkdir -p release/dilithion-windows-x64
cp dilithion-node.exe release/dilithion-windows-x64/
cp dilithion-cli.exe release/dilithion-windows-x64/
cp genesis_gen.exe release/dilithion-windows-x64/

# Create README
cat > release/dilithion-windows-x64/README.txt << 'EOF'
Dilithion Testnet v1.0
======================

Quick Start:
1. Connect to seed node: 170.64.203.134:18444
2. Run: dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=4

Documentation: https://github.com/dilithion/dilithion/blob/main/TESTNET-LAUNCH.md
EOF

# Create ZIP
cd release
zip -r dilithion-windows-x64.zip dilithion-windows-x64/
cd ..
```

#### Linux:
```bash
# Clean build
make clean
make

# Create release directory
mkdir -p release/dilithion-linux-x64
cp dilithion-node release/dilithion-linux-x64/
cp dilithion-cli release/dilithion-linux-x64/
cp genesis_gen release/dilithion-linux-x64/

# Make executable
chmod +x release/dilithion-linux-x64/*

# Create README
cat > release/dilithion-linux-x64/README.txt << 'EOF'
Dilithion Testnet v1.0
======================

Quick Start:
1. Make executable: chmod +x dilithion-node
2. Connect to seed: ./dilithion-node --testnet --addnode=170.64.203.134:18444 --mine --threads=4

Documentation: https://github.com/dilithion/dilithion/blob/main/TESTNET-LAUNCH.md
EOF

# Create tarball
cd release
tar -czf dilithion-linux-x64.tar.gz dilithion-linux-x64/
cd ..
```

#### macOS:
```bash
# Clean build
make clean
make

# Create release directory
mkdir -p release/dilithion-macos-universal
cp dilithion-node release/dilithion-macos-universal/
cp dilithion-cli release/dilithion-macos-universal/
cp genesis_gen release/dilithion-macos-universal/

# Make executable
chmod +x release/dilithion-macos-universal/*

# Create README
cat > release/dilithion-macos-universal/README.txt << 'EOF'
Dilithion Testnet v1.0
======================

Quick Start:
1. Allow execution: xattr -d com.apple.quarantine dilithion-node
2. Connect to seed: ./dilithion-node --testnet --addnode=170.64.203.134:18444 --mine --threads=4

Documentation: https://github.com/dilithion/dilithion/blob/main/TESTNET-LAUNCH.md
EOF

# Create ZIP
cd release
zip -r dilithion-macos-universal.zip dilithion-macos-universal/
cd ..
```

---

## Option 2: GitHub Actions (Automated Multi-Platform Builds)

Create `.github/workflows/release.yml`:

```yaml
name: Build Release Binaries

on:
  release:
    types: [created]

jobs:
  build:
    name: Build ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            artifact_name: dilithion-linux-x64.tar.gz
            asset_name: dilithion-linux-x64.tar.gz
          - os: windows-latest
            artifact_name: dilithion-windows-x64.zip
            asset_name: dilithion-windows-x64.zip
          - os: macos-latest
            artifact_name: dilithion-macos-universal.zip
            asset_name: dilithion-macos-universal.zip

    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          submodules: recursive

      - name: Install dependencies (Ubuntu)
        if: matrix.os == 'ubuntu-latest'
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential

      - name: Build
        run: make

      - name: Package (Linux)
        if: matrix.os == 'ubuntu-latest'
        run: |
          mkdir -p release/dilithion-linux-x64
          cp dilithion-node dilithion-cli genesis_gen release/dilithion-linux-x64/
          chmod +x release/dilithion-linux-x64/*
          echo "Dilithion Testnet v1.0" > release/dilithion-linux-x64/README.txt
          cd release
          tar -czf dilithion-linux-x64.tar.gz dilithion-linux-x64/

      - name: Package (Windows)
        if: matrix.os == 'windows-latest'
        run: |
          mkdir release/dilithion-windows-x64
          cp dilithion-node.exe dilithion-cli.exe genesis_gen.exe release/dilithion-windows-x64/
          echo "Dilithion Testnet v1.0" > release/dilithion-windows-x64/README.txt
          Compress-Archive -Path release/dilithion-windows-x64 -DestinationPath release/dilithion-windows-x64.zip

      - name: Package (macOS)
        if: matrix.os == 'macos-latest'
        run: |
          mkdir -p release/dilithion-macos-universal
          cp dilithion-node dilithion-cli genesis_gen release/dilithion-macos-universal/
          chmod +x release/dilithion-macos-universal/*
          echo "Dilithion Testnet v1.0" > release/dilithion-macos-universal/README.txt
          cd release
          zip -r dilithion-macos-universal.zip dilithion-macos-universal/

      - name: Upload Release Asset
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ github.event.release.upload_url }}
          asset_path: ./release/${{ matrix.artifact_name }}
          asset_name: ${{ matrix.asset_name }}
          asset_content_type: application/octet-stream
```

---

## Uploading to GitHub Release

### Manual Upload:

1. **Build the binaries** (see above)
2. **Go to GitHub Release page**:
   ```
   https://github.com/dilithion/dilithion/releases/tag/v1.0-testnet
   ```
3. **Click "Edit"** (top right)
4. **Drag and drop** the files:
   - `dilithion-windows-x64.zip`
   - `dilithion-linux-x64.tar.gz`
   - `dilithion-macos-universal.zip`
5. **Click "Update release"**

### Command Line Upload (gh CLI):

```bash
# Install GitHub CLI first: https://cli.github.com/

# Upload assets
gh release upload v1.0-testnet \
  release/dilithion-windows-x64.zip \
  release/dilithion-linux-x64.tar.gz \
  release/dilithion-macos-universal.zip \
  --repo dilithion/dilithion
```

---

## Updating Website for Binary Downloads

Once binaries are uploaded, update `website/index.html`:

```html
<div class="download-grid">
    <div class="download-card">
        <div class="platform-icon">🪟</div>
        <h3>Windows</h3>
        <p>Windows 10/11 (64-bit) - Ready to Run</p>
        <a href="https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-windows-x64.zip" class="btn btn-download">Download (.zip)</a>
        <span class="version">v1.0-testnet • No build required</span>
    </div>

    <div class="download-card">
        <div class="platform-icon">🐧</div>
        <h3>Linux</h3>
        <p>Ubuntu, Debian, Fedora, Arch - Ready to Run</p>
        <a href="https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-linux-x64.tar.gz" class="btn btn-download">Download (.tar.gz)</a>
        <span class="version">v1.0-testnet • No build required</span>
    </div>

    <div class="download-card">
        <div class="platform-icon">🍎</div>
        <h3>macOS</h3>
        <p>macOS 11+ (Intel & Apple Silicon) - Ready to Run</p>
        <a href="https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-macos-universal.zip" class="btn btn-download">Download (.zip)</a>
        <span class="version">v1.0-testnet • No build required</span>
    </div>
</div>
```

---

## Testing Binary Releases

Before publishing, test each binary on a clean machine:

### Windows Test:
```powershell
# Extract ZIP
Expand-Archive dilithion-windows-x64.zip

# Test run
cd dilithion-windows-x64
.\dilithion-node.exe --version
.\dilithion-node.exe --testnet --addnode=170.64.203.134:18444
```

### Linux Test:
```bash
# Extract tarball
tar -xzf dilithion-linux-x64.tar.gz

# Test run
cd dilithion-linux-x64
./dilithion-node --version
./dilithion-node --testnet --addnode=170.64.203.134:18444
```

### macOS Test:
```bash
# Extract ZIP
unzip dilithion-macos-universal.zip

# Remove quarantine
cd dilithion-macos-universal
xattr -d com.apple.quarantine dilithion-node

# Test run
./dilithion-node --version
./dilithion-node --testnet --addnode=170.64.203.134:18444
```

---

## Checklist for Release

- [ ] Build binaries for all 3 platforms
- [ ] Test each binary on clean machine
- [ ] Verify no missing dependencies
- [ ] Include README in each package
- [ ] Upload to GitHub release
- [ ] Update website download links
- [ ] Test website download buttons
- [ ] Announce binary availability

---

## File Size Estimates

Expected compressed sizes:
- **Windows**: ~10-20 MB (includes RandomX)
- **Linux**: ~8-15 MB
- **macOS**: ~10-20 MB

GitHub allows up to 2 GB per release asset, so no issues.

---

## Next Steps

1. **Immediate**: Current website now has working source downloads
2. **Short-term**: Build binaries manually and upload to release
3. **Long-term**: Set up GitHub Actions for automated builds on each release

Would you like me to:
- Build the binaries for you right now?
- Set up GitHub Actions automation?
- Both?
