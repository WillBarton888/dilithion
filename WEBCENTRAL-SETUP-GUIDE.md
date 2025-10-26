# Webcentral Setup Guide for Dilithion

**Created:** October 26, 2025
**Status:** In Progress
**Hosting Provider:** Webcentral (Australia)

---

## 📋 Quick Checklist

- [ ] **Step 1:** Set up email accounts (4 addresses)
- [ ] **Step 2:** Configure DNS for dilithion.org
- [ ] **Step 3:** Configure redirect for dilithion.com
- [ ] **Step 4:** Upload website files
- [ ] **Step 5:** Test everything works
- [ ] **Step 6:** Enable SSL certificate

---

## 📧 Step 1: Set Up Email Accounts

### Access Webcentral Email Panel

1. Log into: https://my.webcentral.com.au
2. Navigate to **"My Services"** → Select your hosting package
3. Click **"Email"** or **"Email Accounts"**

### Create These 4 Email Accounts:

**Account 1: team@dilithion.org**
- Purpose: General inquiries
- Mailbox size: 2GB
- Password: [Create strong password]
- Use: Main contact point

**Account 2: security@dilithion.org**
- Purpose: Vulnerability reports
- Mailbox size: 2GB
- Password: [Create strong password]
- Use: Critical security communications

**Account 3: media@dilithion.org**
- Purpose: Press inquiries
- Mailbox size: 1GB
- Password: [Create strong password]
- Use: Media relations

**Account 4: support@dilithion.org**
- Purpose: User help
- Mailbox size: 2GB
- Password: [Create strong password]
- Use: Community support

### Email Forwarding (Optional but Recommended)

If you want all emails to go to one personal inbox:

1. In Webcentral email panel, find **"Forwarders"** or **"Email Forwarding"**
2. Set up forwarding for each:
   - `team@dilithion.org` → `your.personal@email.com`
   - `security@dilithion.org` → `your.personal@email.com`
   - `media@dilithion.org` → `your.personal@email.com`
   - `support@dilithion.org` → `your.personal@email.com`

### Webmail Access

- URL: https://webmail.dilithion.org
- Or: https://webmail.webcentral.com.au
- Username: Full email address (e.g., team@dilithion.org)
- Password: [Password you set]

---

## 🌐 Step 2: Configure DNS for dilithion.org

### Access DNS Management

1. In Webcentral dashboard
2. Go to **"Domains"** → **"Manage Domains"**
3. Select **dilithion.org**
4. Click **"DNS Management"** or **"Advanced DNS"**

### Check Existing MX Records (IMPORTANT - DON'T DELETE!)

**Before changing anything**, note down existing MX records. Should look like:

```
Type: MX
Name: @ (or dilithion.org)
Value: mail.webcentral.com.au (or similar)
Priority: 10
TTL: 3600
```

**Keep these MX records!** They're needed for email to work.

### Choose Your Website Hosting Option:

#### Option A: GitHub Pages (Recommended - Free, Fast CDN)

**Replace/Add A Records:**
```
Type: A
Name: @ (or blank)
Value: 185.199.108.153
TTL: 3600

Type: A
Name: @
Value: 185.199.109.153
TTL: 3600

Type: A
Name: @
Value: 185.199.110.153
TTL: 3600

Type: A
Name: @
Value: 185.199.111.153
TTL: 3600

Type: CNAME
Name: www
Value: willbarton888.github.io
TTL: 3600
```

**Keep MX records!** Don't delete them!

#### Option B: Webcentral Hosting

**Use default A record:**
```
Type: A
Name: @
Value: [Webcentral server IP - ask support or check existing]
TTL: 3600

Type: CNAME
Name: www
Value: dilithion.org
TTL: 3600
```

**Keep MX records!**

---

## 🔀 Step 3: Configure Redirect for dilithion.com

### Method 1: Domain Forwarding (Easiest)

1. In Webcentral dashboard
2. Go to **"Domains"** → Select **dilithion.com**
3. Look for **"Domain Forwarding"** or **"URL Redirect"**
4. Configure:
   - **Forward to:** `https://dilithion.org`
   - **Redirect type:** 301 Permanent
   - **Forward www also:** Yes
5. Save

### Method 2: DNS + .htaccess (If no forwarding feature)

**DNS for dilithion.com:**
```
Type: A
Name: @
Value: [Same IP as dilithion.org]
TTL: 3600

Type: CNAME
Name: www
Value: dilithion.org
TTL: 3600
```

Then use the `.htaccess` file (already created in website/ folder) to handle redirects.

---

## 📤 Step 4: Upload Website Files

### Get FTP/File Manager Access

**In Webcentral control panel:**
1. Look for **"FTP Accounts"** or **"File Manager"**
2. Note credentials:
   - **FTP Host:** ftp.dilithion.org (or IP address)
   - **Username:** [Provided by Webcentral]
   - **Password:** [Set or provided by Webcentral]
   - **Port:** 21 (FTP) or 22 (SFTP)

### Upload Files

**Option A: Use FileZilla (Recommended)**

1. Download FileZilla: https://filezilla-project.org/
2. Connect:
   - Host: `ftp.dilithion.org`
   - Username: [Your FTP username]
   - Password: [Your FTP password]
   - Port: 21
3. Navigate to `public_html` or `www` folder (web root)
4. Upload these files from `C:\Users\will\dilithion\website\`:
   - `index.html`
   - `style.css`
   - `script.js`
   - `POST-QUANTUM-CRYPTO-COURSE.md`
   - `README.md`
   - `.htaccess` ⚠️ Important for redirects!

**Option B: Use Webcentral File Manager**

1. In control panel, click **"File Manager"**
2. Navigate to `public_html` or `www`
3. Click **"Upload"**
4. Select all files from `website/` folder
5. Upload

### Set Correct Permissions

After upload, set permissions:
- **Files:** 644 (rw-r--r--)
- **Folders:** 755 (rwxr-xr-x)

In File Manager or FTP client, right-click files → Permissions → Set to 644

---

## ✅ Step 5: Test Everything

### Test 1: Website Access

Wait 10-60 minutes for DNS propagation, then test:

- [ ] https://dilithion.org → Website loads ✓
- [ ] https://www.dilithion.org → Redirects to dilithion.org ✓
- [ ] https://dilithion.com → Redirects to dilithion.org ✓
- [ ] https://www.dilithion.com → Redirects to dilithion.org ✓

**If not working yet:** DNS takes time. Check at https://dnschecker.org

### Test 2: Email Delivery

**Test receiving:**
- [ ] Send email to team@dilithion.org from personal email
- [ ] Wait 2 minutes
- [ ] Check it arrived (inbox or forward destination)

**Test sending:**
- [ ] Log into webmail.dilithion.org
- [ ] Username: team@dilithion.org
- [ ] Send test email to yourself
- [ ] Check it doesn't go to spam

**Test all 4 addresses:**
- [ ] team@dilithion.org
- [ ] security@dilithion.org
- [ ] media@dilithion.org
- [ ] support@dilithion.org

### Test 3: SSL Certificate

- [ ] Visit https://dilithion.org
- [ ] Check for padlock icon 🔒 in browser
- [ ] Click padlock → Certificate should be valid
- [ ] No security warnings

**If no SSL:**
- Webcentral usually auto-installs Let's Encrypt SSL
- Contact Webcentral support to enable if not automatic
- May take 24 hours after DNS propagation

---

## 🔐 Step 6: Enable SSL Certificate

### Webcentral Auto-SSL (Let's Encrypt)

1. In control panel, go to **"SSL Certificates"**
2. Look for **"AutoSSL"** or **"Let's Encrypt"**
3. Click **"Enable"** for dilithion.org
4. May take 5-60 minutes to activate

### Or Contact Webcentral Support

If you can't find SSL options:
- **Email:** support@webcentral.com.au
- **Phone:** 1300 638 734
- **Request:** "Please enable AutoSSL/Let's Encrypt for dilithion.org"

---

## 📧 Email Client Setup (For Your Reference)

If you want to use Outlook, Thunderbird, or phone email app:

### Incoming Mail Server (IMAP - Recommended)
```
Server: mail.dilithion.org (or mail.webcentral.com.au)
Port: 993
Security: SSL/TLS
Username: team@dilithion.org
Password: [Your password]
```

### Incoming Mail Server (POP3 - Alternative)
```
Server: mail.dilithion.org
Port: 995
Security: SSL/TLS
Username: team@dilithion.org
Password: [Your password]
```

### Outgoing Mail Server (SMTP)
```
Server: mail.dilithion.org (or smtp.webcentral.com.au)
Port: 465 (SSL) or 587 (TLS)
Security: SSL/TLS
Authentication: Required
Username: team@dilithion.org
Password: [Your password]
```

**Ask Webcentral support for exact server names if these don't work.**

---

## 🆘 Troubleshooting

### Website Not Loading

**Issue:** dilithion.org shows error or old page
**Solution:**
1. Check DNS propagation: https://dnschecker.org
2. Wait up to 48 hours for global DNS propagation
3. Clear browser cache (Ctrl+Shift+Delete)
4. Check files uploaded to correct folder (public_html or www)

### Email Not Receiving

**Issue:** Emails not arriving
**Solution:**
1. Check MX records are correct: https://mxtoolbox.com
2. Verify email account created (login to webmail)
3. Check spam folder
4. Verify sender's email server isn't blacklisted

### SSL Certificate Error

**Issue:** "Not Secure" warning or SSL error
**Solution:**
1. Wait 24 hours after DNS setup for auto-SSL
2. Contact Webcentral support to manually install
3. Check DNS is pointing to correct server

### Redirect Not Working

**Issue:** dilithion.com doesn't redirect to .org
**Solution:**
1. Check `.htaccess` file uploaded correctly
2. Verify DNS for dilithion.com points to same server
3. Wait for DNS propagation
4. Test with domain forwarding feature instead

---

## 📞 Webcentral Support

If you get stuck:

**Support Contact:**
- **Phone:** 1300 638 734 (Australia)
- **Email:** support@webcentral.com.au
- **Live Chat:** Available on their website
- **Support Portal:** https://my.webcentral.com.au

**Tell them:**
- "I need help setting up dilithion.org with email and website hosting"
- "I need AutoSSL/Let's Encrypt enabled"
- "I need help with DNS configuration"

---

## ✅ Completion Checklist

Once everything is set up:

- [ ] dilithion.org website loading with HTTPS
- [ ] dilithion.com redirects to dilithion.org
- [ ] All 4 email addresses working
- [ ] SSL certificate active (padlock showing)
- [ ] Can send/receive emails
- [ ] Website shows your Dilithion educational content
- [ ] DNS propagated globally (check dnschecker.org)

---

## 🚀 Next Steps After Setup

Once hosting and email are working:

1. **Week 2 Day 2 Afternoon:** Set up social media
   - Create Twitter @DilithionCoin
   - Create Discord server
   - Create r/dilithion subreddit

2. **Week 2 Day 2 Evening:** First announcement
   - Post to all social channels
   - Link to dilithion.org website

3. **Week 2 Day 3-4:** Community outreach
   - Post to r/cryptography
   - Post to BitcoinTalk
   - Post to HackerNews

---

**Need help? Contact me (Claude) with specific questions about the setup!**

**Last updated:** October 26, 2025
