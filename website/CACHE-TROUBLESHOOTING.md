# Website Cache Troubleshooting Guide

## Problem
The dilithion.org website continues to serve v1.0.6 even after uploading the updated index.html file that contains v1.0.7. Hard refreshes don't help.

## Root Cause
This is a **server-side or CDN caching issue**, not a browser cache issue.

## Solution Steps (In Order)

### 1. Verify Upload Path
**Check that the file is being uploaded to the correct location:**
- Most web hosts use `/public_html/` or `/www/` or `/htdocs/`
- Verify you're uploading to the **root web directory**, not a subdirectory
- After upload, check the file modification timestamp on the server matches your upload time

### 2. Check for CDN or Caching Service
**If dilithion.org uses Cloudflare, CloudFront, or similar:**
- Log into your DNS/hosting provider (where you manage dilithion.org)
- Look for "Caching" or "CDN" settings
- **Purge/Clear all caches**
- Common providers:
  - **Cloudflare**: Go to "Caching" → "Purge Everything"
  - **CloudFront**: Create an invalidation for `/*`
  - **Other CDNs**: Look for "Clear Cache" or "Invalidation" option

### 3. Clear Server-Side Caching
**Most hosting providers have server caching:**

**For cPanel hosting:**
1. Log into cPanel
2. Go to "File Manager"
3. Look for `.htaccess` file in the web root
4. Check if there are caching rules (lines with `ExpiresByType` or `Cache-Control`)
5. Temporarily disable or add this to the top of `.htaccess`:
```apache
# Disable caching for testing
<FilesMatch "\.(html)$">
    Header set Cache-Control "no-cache, no-store, must-revalidate"
    Header set Pragma "no-cache"
    Header set Expires 0
</FilesMatch>
```

**For other hosting:**
- Check hosting control panel for "Cache Manager" or similar
- Look for options like "Varnish Cache", "Nginx Cache", "LiteSpeed Cache"
- Disable or purge these caches

### 4. Verify File Permissions
**Ensure the web server can read the file:**
```bash
# File should have permissions like 644 (rw-r--r--)
# If using SSH/FTP, set:
chmod 644 index.html
```

### 5. Check for Multiple Index Files
**The web server might be serving a different file:**
- Check if there's `index.htm` (no 'l') taking precedence
- Check if there's `default.html` or `home.html`
- Delete or rename any old index files

### 6. Force Cache Bust with Timestamp
**Temporarily add a query string to test:**
- Have the external miner try: `https://dilithion.org/?v=20251115`
- If this shows v1.0.7, it confirms caching is the issue

### 7. Contact Hosting Provider
**If none of the above work:**
- Contact your web hosting support
- Tell them: "I've uploaded a new index.html but the old cached version keeps serving"
- Ask them to:
  - Clear all server-side caches
  - Verify the file timestamp on the server
  - Check if there's a CDN or reverse proxy in front of the site

## Quick Verification Commands

**If you have SSH access to the web server:**
```bash
# Check file modification time
ls -lh /path/to/webroot/index.html

# Check file content
grep "v1.0.7" /path/to/webroot/index.html

# Check for .htaccess caching rules
cat /path/to/webroot/.htaccess | grep -i cache
```

## Expected Timeline
- **CDN cache purge**: Takes 5-15 minutes to propagate
- **Server cache clear**: Usually immediate
- **Browser hard refresh**: Immediate (but this wasn't the issue)

## Verification After Fix
Test that the update worked:
```bash
curl -I https://dilithion.org/
# Look for Cache-Control headers

curl -s https://dilithion.org/ | grep "v1.0.7"
# Should return matching lines
```

## Most Likely Cause
Based on the symptoms (local file correct, GitHub correct, multiple uploads failed, hard refresh failed), the most likely culprit is:

**1. Cloudflare or CDN caching (90% probability)**
**2. Server-side caching (Varnish/Nginx/LiteSpeed) (8% probability)**
**3. Wrong upload path (2% probability)**
