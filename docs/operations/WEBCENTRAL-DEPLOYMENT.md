# Webcentral Deployment Guide - dilithion.org

Complete guide to deploy the Dilithion website to your Webcentral hosting.

---

## Prerequisites

- ✅ Webcentral hosting account (you have this)
- ✅ Domain: dilithion.org (you own this)
- ✅ FTP/SFTP credentials for Webcentral
- ✅ Website files ready (in `website/` directory)

---

## Step 1: Gather Your Webcentral Credentials

You'll need:
- **FTP Host:** (Usually `ftp.dilithion.org` or provided by Webcentral)
- **FTP Username:** (Your Webcentral username)
- **FTP Password:** (Your Webcentral password)
- **Port:** 21 (FTP) or 22 (SFTP)

**Where to find these:**
1. Log in to Webcentral control panel
2. Look for "FTP Accounts" or "File Manager"
3. Note down the FTP credentials

---

## Step 2: Choose Upload Method

### Option A: FileZilla (Recommended - Visual Interface)

**Download FileZilla:**
- https://filezilla-project.org/download.php?type=client
- Free FTP client for Windows

**Connect to Webcentral:**
1. Open FileZilla
2. Enter:
   - **Host:** `ftp.dilithion.org` (or your Webcentral FTP host)
   - **Username:** Your Webcentral username
   - **Password:** Your Webcentral password
   - **Port:** 21
3. Click "Quickconnect"

**Upload Files:**
1. Left side: Navigate to `C:\Users\will\dilithion\website\`
2. Right side: Navigate to `public_html` or `www` directory
3. Select all files in website folder
4. Drag to right side to upload
5. Wait for upload to complete

### Option B: Windows Command Line (FTP)

```cmd
cd C:\Users\will\dilithion\website
ftp ftp.dilithion.org
# Enter username when prompted
# Enter password when prompted
cd public_html
mput *
quit
```

### Option C: Webcentral File Manager (Browser)

1. Log in to Webcentral control panel
2. Open "File Manager"
3. Navigate to `public_html` or `www`
4. Upload all files from `C:\Users\will\dilithion\website\`

---

## Step 3: Files to Upload

Upload ALL these files from `website/` directory to Webcentral:

**Essential Files:**
```
index.html                      (Main website)
style.css                       (Styles)
script.js                       (JavaScript)
WHITEPAPER.html                 (Whitepaper page)
privacy-policy.html             (Privacy policy)
terms-of-service.html           (Terms)
Dilithion-Whitepaper-v1.0.pdf   (PDF version)
POST-QUANTUM-CRYPTO-COURSE.md   (Educational content)
README.md                       (Website documentation)
```

**Total size:** ~1-2 MB

---

## Step 4: Verify Directory Structure

On Webcentral server, your structure should be:

```
public_html/  (or www/)
├── index.html
├── style.css
├── script.js
├── WHITEPAPER.html
├── privacy-policy.html
├── terms-of-service.html
├── Dilithion-Whitepaper-v1.0.pdf
└── POST-QUANTUM-CRYPTO-COURSE.md
```

**Root directory:** Make sure files are in `public_html` NOT in a subdirectory.

---

## Step 5: Test the Website

### Test in Browser

Open these URLs and verify they work:

1. **Homepage:** https://dilithion.org/
   - Should show testnet banner
   - Countdown to mainnet
   - "TESTNET IS NOW LIVE" message

2. **Whitepaper:** https://dilithion.org/WHITEPAPER.html
   - Should load whitepaper page

3. **Privacy Policy:** https://dilithion.org/privacy-policy.html
   - Should load privacy policy

4. **Terms:** https://dilithion.org/terms-of-service.html
   - Should load terms

5. **PDF:** https://dilithion.org/Dilithion-Whitepaper-v1.0.pdf
   - Should download or view PDF

### Check Functionality

- [ ] Testnet banner visible and animated (green glow)
- [ ] All download links work (point to GitHub v1.0-testnet)
- [ ] Countdown to January 1, 2026 works
- [ ] "Join the Testnet" section displays
- [ ] All GitHub links work
- [ ] Footer shows testnet disclaimer
- [ ] Mobile responsive (test on phone)
- [ ] No broken images or CSS

---

## Step 6: Setup SSL Certificate (HTTPS)

**Important:** Your site should use HTTPS for security.

### Check Current Status

Visit: https://dilithion.org/

**If it works:** ✅ SSL already configured

**If it doesn't work or shows warning:** Configure SSL:

### Configure SSL on Webcentral

1. Log in to Webcentral control panel
2. Look for "SSL Certificates" or "Security"
3. Options:
   - **Free SSL (Let's Encrypt):** Usually available
   - **Paid SSL:** If needed for business

4. Enable SSL for dilithion.org
5. Wait 5-10 minutes for propagation
6. Test: https://dilithion.org/

### Force HTTPS Redirect

Create `.htaccess` file in `public_html`:

```apache
# Force HTTPS
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

**How to create:**
1. In FileZilla: Right-click → Create new file → `.htaccess`
2. Paste the content above
3. Save and upload

---

## Step 7: Update Repository Links

Once website is live, update these files:

### Update README.md

Add website link to top of README:

```markdown
# Dilithion - Experimental Post-Quantum Cryptocurrency

🌐 **Website:** https://dilithion.org/
🚀 **Testnet:** LIVE NOW
```

### Update TESTNET-LAUNCH.md

Add website reference:

```markdown
## Official Links

- 🌐 **Website:** https://dilithion.org/
- 💻 **GitHub:** https://github.com/dilithion/dilithion
- 📖 **Testnet Guide:** [TESTNET-LAUNCH.md](TESTNET-LAUNCH.md)
```

### Commit and Push

```bash
git add README.md TESTNET-LAUNCH.md
git commit -m "DOCS: Add dilithion.org website link"
git push origin main
```

---

## Step 8: DNS Verification (Optional)

Verify DNS is pointing correctly:

**Check DNS:**
- Open Command Prompt
- Run: `nslookup dilithion.org`
- Should show your Webcentral IP address

**If DNS not configured:**
1. Log in to your domain registrar (where you bought dilithion.org)
2. Update DNS nameservers to Webcentral nameservers
3. Wait 24-48 hours for propagation

---

## Troubleshooting

### Website Shows 404 Error

**Fix:**
- Ensure files are in `public_html` NOT a subdirectory
- Check file names are exact (case-sensitive)
- Verify `index.html` exists

### Styles Not Loading

**Fix:**
- Upload `style.css` to same directory as `index.html`
- Check file permissions (should be 644)
- Clear browser cache (Ctrl+F5)

### Links Broken

**Fix:**
- Verify all files uploaded
- Check file paths in `index.html`
- Test each link individually

### SSL Certificate Error

**Fix:**
- Wait 10-15 minutes after enabling SSL
- Clear browser cache
- Contact Webcentral support if persists

---

## Quick Deployment Checklist

```
Pre-Deployment:
[ ] Have Webcentral FTP credentials
[ ] Have FileZilla installed (or FTP client)
[ ] Website files ready in website/ directory

Upload:
[ ] Connect to Webcentral FTP
[ ] Upload all files to public_html/
[ ] Verify directory structure correct
[ ] Check file permissions

Testing:
[ ] Visit https://dilithion.org/
[ ] Test all pages load
[ ] Test all links work
[ ] Check mobile responsive
[ ] Verify SSL certificate

Post-Deployment:
[ ] Enable SSL/HTTPS
[ ] Create .htaccess for HTTPS redirect
[ ] Update README.md with website link
[ ] Commit and push to GitHub
[ ] Announce on social media
```

---

## Expected Results

After successful deployment:

✅ **Homepage:** https://dilithion.org/
- Shows testnet banner
- Countdown to mainnet
- All links working

✅ **SSL:** HTTPS enabled (green padlock)

✅ **Performance:** Fast loading (<2 seconds)

✅ **SEO:** Proper meta tags and descriptions

✅ **Mobile:** Responsive on all devices

---

## Support

**Webcentral Support:**
- Phone: Check your Webcentral account
- Email: Check your Webcentral account
- Control Panel: Log in for live chat

**FileZilla Support:**
- Documentation: https://wiki.filezilla-project.org/
- Forum: https://forum.filezilla-project.org/

**Dilithion Website Issues:**
- GitHub: https://github.com/dilithion/dilithion/issues

---

## Cost

**Webcentral Hosting:** You already pay for this
**Domain (dilithion.org):** You already own this
**SSL Certificate:** Usually free (Let's Encrypt)

**Total Additional Cost:** $0 ✅

---

## Deployment Time Estimate

- **File Upload:** 5 minutes
- **SSL Setup:** 10 minutes
- **Testing:** 5 minutes
- **GitHub Updates:** 5 minutes

**Total Time:** ~25 minutes

---

## Next Steps After Deployment

1. **Share the website:**
   - Add to GitHub README
   - Add to TESTNET-LAUNCH.md
   - Post on social media

2. **Monitor:**
   - Check website loads
   - Monitor hosting resources
   - Check SSL certificate expiry

3. **Update regularly:**
   - Keep content current
   - Update testnet status
   - Add community links as created

---

## Ready to Deploy!

Follow the steps above to get dilithion.org live. 🚀

**Start with Step 1** - Gather your Webcentral credentials and let me know when you're ready to upload!

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
