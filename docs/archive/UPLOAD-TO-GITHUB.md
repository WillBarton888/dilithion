# How to Upload Release Assets to GitHub

## Current Status

- **Release**: v1.0-testnet exists
- **Release ID**: 257731183
- **Upload URL**: https://uploads.github.com/repos/dilithion/dilithion/releases/257731183/assets
- **Current Assets**: None (source code only)

## Available Packages

- ✅ `releases/dilithion-testnet-v1.0.0-linux-x64.tar.gz` (Ready)
- ⏳ `releases/dilithion-testnet-v1.0.0-windows-x64.zip` (Need Windows build)
- ⏳ `releases/dilithion-testnet-v1.0.0-macos-x64.tar.gz` (Need macOS build)

## Method 1: Using GitHub Web Interface (Easiest)

1. Go to: https://github.com/dilithion/dilithion/releases/tag/v1.0-testnet

2. Click "Edit release" button (top right)

3. Scroll to "Attach binaries" section

4. Drag and drop (or click to browse):
   - `releases/dilithion-testnet-v1.0.0-linux-x64.tar.gz`
   - (Add Windows and macOS packages when available)

5. Click "Update release"

6. Verify downloads work by clicking each asset link

## Method 2: Using GitHub CLI

If you have `gh` installed:

```bash
# Upload Linux package
gh release upload v1.0-testnet releases/dilithion-testnet-v1.0.0-linux-x64.tar.gz

# When Windows and macOS are ready:
gh release upload v1.0-testnet releases/dilithion-testnet-v1.0.0-windows-x64.zip
gh release upload v1.0-testnet releases/dilithion-testnet-v1.0.0-macos-x64.tar.gz
```

## Method 3: Using curl (Advanced)

Requires GitHub Personal Access Token with `repo` scope.

```bash
# Set your GitHub token
GITHUB_TOKEN="your_token_here"

# Upload Linux package
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Content-Type: application/gzip" \
  --data-binary @releases/dilithion-testnet-v1.0.0-linux-x64.tar.gz \
  "https://uploads.github.com/repos/dilithion/dilithion/releases/257731183/assets?name=dilithion-testnet-v1.0.0-linux-x64.tar.gz"
```

## Direct Download URLs (After Upload)

Once uploaded, the download URLs will be:

**Linux**:
```
https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-testnet-v1.0.0-linux-x64.tar.gz
```

**Windows** (when ready):
```
https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-testnet-v1.0.0-windows-x64.zip
```

**macOS** (when ready):
```
https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-testnet-v1.0.0-macos-x64.tar.gz
```

## After Upload: Update Website

Once binaries are uploaded, update `website/index.html` with direct download links.

Replace the current source code download links with:

```html
<div class="download-section">
  <h2>Download Testnet</h2>

  <!-- Linux -->
  <a href="https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-testnet-v1.0.0-linux-x64.tar.gz"
     class="btn btn-download">
    <i class="fab fa-linux"></i> Download for Linux (.tar.gz)
  </a>

  <!-- Windows (when ready) -->
  <a href="https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-testnet-v1.0.0-windows-x64.zip"
     class="btn btn-download">
    <i class="fab fa-windows"></i> Download for Windows (.zip)
  </a>

  <!-- macOS (when ready) -->
  <a href="https://github.com/dilithion/dilithion/releases/download/v1.0-testnet/dilithion-testnet-v1.0.0-macos-x64.tar.gz"
     class="btn btn-download">
    <i class="fab fa-apple"></i> Download for macOS (.tar.gz)
  </a>
</div>
```

## Verification

After uploading, verify:

1. **Download Works**: Click the download link on GitHub release page
2. **File Size Correct**:
   - Linux: ~1.1 MB
   - Windows: TBD
   - macOS: TBD
3. **Extract Works**:
   ```bash
   tar -xzf dilithion-testnet-v1.0.0-linux-x64.tar.gz
   cd dilithion-testnet-v1.0.0-linux-x64
   ls -la
   ```
4. **Binary Runs**:
   ```bash
   ./start-mining.sh
   ```

## Next Steps

1. ✅ Upload Linux package to v1.0-testnet release
2. ⏳ Build Windows binaries on Windows machine
3. ⏳ Package Windows release
4. ⏳ Upload Windows package
5. ⏳ Build macOS binaries on Mac machine
6. ⏳ Package macOS release
7. ⏳ Upload macOS package
8. ✅ Update website with all download links

## Notes

- Current release has only source code (no binaries)
- Linux package is ready for immediate upload
- Windows and macOS require building on native platforms
- See `RELEASE-PACKAGING-GUIDE.md` for build instructions
