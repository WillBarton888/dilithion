# WebCentral Cache Clearing Guide

## Problem
dilithion.org is hosted on WebCentral and continues to show v1.0.6 despite uploading the updated index.html file with v1.0.7.

## Root Cause
WebCentral uses **cPanel with server-side caching** (usually Varnish or LiteSpeed Cache). File uploads work, but the cached version is still being served.

## Solution Steps for WebCentral

### Method 1: Clear Cache via cPanel (Recommended)

1. **Log into WebCentral Control Panel**
   - Go to: https://www.webcentral.com.au/
   - Click "Login" → "My Services"
   - Find your dilithion.org hosting package
   - Click "Manage" or "cPanel Login"

2. **Access cPanel**
   - Once in cPanel, look for these cache-related tools:

3. **Clear LiteSpeed Cache (if available)**
   - In cPanel, search for "LiteSpeed Web Cache Manager"
   - Click "Purge All" or "Flush All"
   - This clears the entire cache immediately

4. **Clear Varnish Cache (if no LiteSpeed)**
   - Look for "Varnish Cache" or "Cache Manager"
   - Click "Purge Cache" or "Clear All"

5. **Check .htaccess File**
   - In cPanel, go to "File Manager"
   - Navigate to `/public_html/`
   - Look for `.htaccess` file
   - Check if there are caching headers like:
     ```apache
     ExpiresActive On
     ExpiresByType text/html "access plus 1 day"
     ```
   - Temporarily add this to the TOP of .htaccess to disable HTML caching:
     ```apache
     # Disable HTML caching during update
     <FilesMatch "\.(html)$">
         Header set Cache-Control "no-cache, no-store, must-revalidate"
         Header set Pragma "no-cache"
         Header set Expires 0
     </FilesMatch>
     ```

### Method 2: Clear via File Manager

1. **Verify Upload Location**
   - In cPanel File Manager, go to `/public_html/`
   - Right-click `index.html`
   - Check "Last Modified" date/time
   - Should show your recent upload time
   - If NOT recent, you may be uploading to the wrong directory

2. **Force Cache Bust**
   - After verifying the file is correct, rename the old file:
     - Rename `index.html` to `index_old.html`
   - Upload the new file as `index.html`
   - This forces the web server to recognize it as a new file

### Method 3: Contact WebCentral Support

If the above don't work, contact WebCentral support:

**WebCentral Support:**
- Phone: 13 24 85 (Australia)
- Email: support@webcentral.com.au
- Live Chat: Available in your WebCentral dashboard

**Tell them:**
"I've uploaded a new index.html file to my website (dilithion.org) but the old cached version is still being served. Can you please clear all caching for my domain? I've confirmed the file is uploaded correctly in cPanel File Manager, but visitors are still seeing the old version even after hard refresh."

### Method 4: Using FTP/SFTP Upload

If you're uploading via FTP client (FileZilla, etc.):

1. **Verify FTP Path**
   - Ensure you're uploading to: `/public_html/index.html`
   - NOT `/www/` or `/httpdocs/` (these are symlinks on some hosts)

2. **Check File Permissions**
   - File should have permissions: `644` (rw-r--r--)
   - Set in FTP client: Right-click → File Permissions → Set to 644

3. **Force Overwrite**
   - Delete the old `index.html` on the server first
   - Then upload the new file
   - This ensures no partial upload issues

## WebCentral Caching Architecture

WebCentral typically uses:
- **LiteSpeed Web Server** (with built-in cache) OR
- **Apache + Varnish** (reverse proxy cache)
- **Browser Cache Headers** (set via .htaccess)

All of these cache HTML files aggressively for performance.

## Verification After Clearing Cache

1. **Wait 5-10 minutes** after clearing cache (for propagation)

2. **Test from command line** (to bypass browser cache):
   ```bash
   curl -s https://dilithion.org/ | grep "v1.0.7"
   ```
   Should return matching lines if successful.

3. **Test in browser** with hard refresh:
   - Windows: Ctrl+Shift+R or Ctrl+F5
   - Mac: Cmd+Shift+R
   - Should now show v1.0.7

4. **Test download link**:
   - Click the Windows download button
   - Verify it downloads: `dilithion-testnet-v1.0.7-windows-x64.zip`
   - NOT v1.0.6

## Expected Timeline

- **LiteSpeed/Varnish cache purge**: Immediate to 5 minutes
- **DNS propagation**: Not relevant (same file, same domain)
- **Browser cache**: Immediate with hard refresh

## Most Likely Issue

Based on WebCentral's infrastructure, the issue is **99% likely** to be:
1. **LiteSpeed Cache** (if on newer WebCentral plans) - Most common
2. **Varnish Cache** (if on older plans)
3. **.htaccess caching headers** - Less common but possible

## Quick Fix (If Urgent)

If you need to get the external miner connected IMMEDIATELY:

1. **Temporary workaround**: Give them the direct GitHub download link:
   ```
   https://github.com/dilithion/dilithion/releases/download/v1.0.7-testnet/dilithion-testnet-v1.0.7-windows-x64.zip
   ```

2. This bypasses the website entirely while you fix the cache issue.

## After Fix - Remove Temporary .htaccess Rules

Once cache is cleared and website shows v1.0.7, remove the temporary no-cache rules from .htaccess to restore normal performance caching.

---

**Priority Actions (In Order):**
1. Log into cPanel
2. Find "LiteSpeed Web Cache Manager" or "Cache Manager"
3. Click "Purge All" / "Flush All"
4. Wait 5 minutes
5. Test: `curl -s https://dilithion.org/ | grep "v1.0.7"`
6. If still fails, contact WebCentral support

This should resolve the issue within 10-15 minutes.
