# Website Update for v1.0.9 Windows Package Rebuild

**Date:** November 16, 2025
**File Updated:** `website/index.html`
**Purpose:** Reflect corrected v1.0.9 Windows package with fixed launcher scripts

---

## Changes Made to index.html

### 1. Updated Banner Date and Messaging
**Line 199:**
- OLD: `Nov 15, 2025`
- NEW: `Nov 16, 2025`
- Added: "launcher scripts updated" to message

```html
✅ LATEST VERSION (Nov 16, 2025): <strong>v1.0.9 for all platforms is now available!</strong>
Critical bugfix release - Windows path validation fixed, launcher scripts updated, works from Desktop now!
```

### 2. Updated Windows Download Section

**Line 528 - Release Date:**
- OLD: `v1.0.9 (Nov 15)`
- NEW: `v1.0.9 (Nov 16)`

**Line 530 - File Size:**
- OLD: `Download ZIP (2.6 MB)`
- NEW: `Download ZIP (3.5 MB)`

**Line 536 - Bug Fix Description:**
- OLD: `Clean launcher scripts without old seed nodes.`
- NEW: `Updated launcher scripts with modern error handling. No more "forbidden characters" errors or old seed node references.`

**Line 539 - SHA256 Checksum:**
- OLD: `d46cd1bcff5f6e7949e1de0fe565baf659f273bfa9216c053370c0380b886b5a`
- NEW: `77fcaa46f97778c50c6ea0c3fccb65fe7b77c94e8f2e575cc603a738aa808cae`

---

## Summary of Updates

| Field | Old Value | New Value |
|-------|-----------|-----------|
| **Banner Date** | Nov 15, 2025 | Nov 16, 2025 |
| **Windows Release Date** | Nov 15 | Nov 16 |
| **ZIP File Size** | 2.6 MB | 3.5 MB |
| **SHA256 Checksum** | d46cd1bcff5f6e7949e1de0fe565baf6... | 77fcaa46f97778c50c6ea0c3fccb65fe... |
| **Description** | Clean launcher scripts | Updated with modern error handling |

---

## Verification

✅ Old SHA256 checksum removed from website
✅ New SHA256 checksum added (matches GitHub release)
✅ File size updated to 3.5 MB (correct for new package)
✅ Release date updated to Nov 16
✅ Description updated to mention launcher script improvements

---

## What Users Will See

### Before Update:
- Windows package dated Nov 15
- File size listed as 2.6 MB
- SHA256 ending in `...b886b5a` (old broken package)
- Message about "clean launcher scripts"

### After Update:
- Windows package dated Nov 16
- File size listed as 3.5 MB
- SHA256 ending in `...aa808cae` (new fixed package)
- Message about "updated launcher scripts with modern error handling"

---

## Files Ready for Upload to dilithion.org

**Primary File:**
- ✅ `website/index.html` - Updated with v1.0.9 corrections

**Supporting Files (no changes needed):**
- `website/style.css` - No changes
- `website/dilithion-logo-256.png` - No changes
- `website/favicon.ico` - No changes

---

## Upload Instructions

Upload the following file to dilithion.org:

```bash
# Upload updated index.html
scp website/index.html user@dilithion.org:/var/www/html/

# Or via FTP/control panel
# Upload: website/index.html → /public_html/index.html
```

---

## Testing After Upload

1. Visit https://dilithion.org
2. Verify banner shows "Nov 16, 2025"
3. Scroll to Windows download section
4. Verify:
   - ✅ Date shows "v1.0.9 (Nov 16)"
   - ✅ Download button shows "3.5 MB"
   - ✅ SHA256 checksum: `77fcaa46f97778c50c6ea0c3fccb65fe7b77c94e8f2e575cc603a738aa808cae`
   - ✅ Description mentions "modern error handling"

---

## Cross-Platform Consistency

**Linux Section:** No changes needed
- Date: Nov 15 ✓
- SHA256: `c519466f6e383b3a31612d6368cd685ae30302f555bc390140999620b06a0052` ✓

**macOS Section:** No changes needed
- Date: Nov 15 ✓
- SHA256: `18607e9b0735854fc14992c412505c1a37003d5f168791bcc36d51401a56745c` ✓

**Windows Section:** Updated
- Date: Nov 16 ✓
- SHA256: `77fcaa46f97778c50c6ea0c3fccb65fe7b77c94e8f2e575cc603a738aa808cae` ✓

---

## Status

✅ **COMPLETE** - index.html updated and ready for upload to dilithion.org
