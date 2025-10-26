# Dilithion Launch Website

Professional launch website for Dilithion cryptocurrency with countdown timer and live network dashboard.

---

## Features

- **Countdown Timer** to January 1, 2026 mainnet launch
- **Live Network Dashboard** showing real-time statistics:
  - Block height
  - Network hash rate
  - Difficulty
  - Total supply mined
  - Current block reward
  - Blocks until next halving
  - Last block time
  - Average block time
- **Getting Started Guide** with step-by-step instructions
- **Download Section** for all platforms (Windows, Linux, macOS)
- **Technical Specifications** table
- **Responsive Design** (works on desktop, tablet, mobile)
- **Modern UI** with dark theme and gradient accents

---

## Quick Start

### Local Testing

1. **Open the website:**
   ```bash
   # Just open index.html in your browser
   # Windows:
   start website/index.html

   # Or double-click: C:\Users\will\dilithion\website\index.html
   ```

2. **View locally:**
   - The website works entirely as static HTML/CSS/JS
   - No build step required
   - No server required (for basic viewing)

### Live Dashboard (After Launch)

The dashboard will automatically connect to your local Dilithion node when:
- Network launches (January 1, 2026)
- Node is running on `localhost:9332`

**To test dashboard before launch:**
1. Start your Dilithion node: `./dilithion-node`
2. The website will detect the RPC endpoint
3. Dashboard updates every 5 seconds

---

## File Structure

```
website/
├── index.html      # Main website HTML
├── style.css       # Styling (dark theme, responsive)
├── script.js       # Countdown timer + dashboard logic
└── README.md       # This file
```

---

## Configuration

### Change Launch Date

Edit `script.js` line 8:
```javascript
const LAUNCH_DATE = new Date('2026-01-01T00:00:00Z').getTime();
```

### Change RPC Endpoint

Edit `script.js` line 9:
```javascript
const RPC_ENDPOINT = 'http://localhost:9332';
```

For remote node:
```javascript
const RPC_ENDPOINT = 'http://your-node-ip:9332';
```

### Update Interval

Edit `script.js` line 10:
```javascript
const UPDATE_INTERVAL = 5000; // milliseconds (5 seconds)
```

---

## Deployment Options

### Option 1: Static Hosting (Recommended)

Host on any static site hosting service:

**GitHub Pages (Free):**
```bash
# Create a new repo: dilithion-website
# Push website/ contents
# Enable GitHub Pages in repo settings

# Or use gh-pages branch:
git checkout -b gh-pages
git add website/*
git commit -m "Deploy website"
git push origin gh-pages
```

**Netlify (Free):**
1. Drag & drop `website/` folder to netlify.com
2. Custom domain: `dilithion.org`
3. Auto-deploy on git push

**Vercel (Free):**
```bash
npm i -g vercel
cd website
vercel
```

**Cloudflare Pages (Free):**
1. Connect GitHub repo
2. Build command: (none needed)
3. Output directory: `website`

### Option 2: Simple HTTP Server

For local testing with live reload:

**Python:**
```bash
cd website
python -m http.server 8000
# Visit: http://localhost:8000
```

**Node.js:**
```bash
npx http-server website -p 8000
```

**PHP:**
```bash
cd website
php -S localhost:8000
```

### Option 3: Full Web Server

**Nginx:**
```nginx
server {
    listen 80;
    server_name dilithion.org;
    root /var/www/dilithion/website;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

**Apache:**
```apache
<VirtualHost *:80>
    ServerName dilithion.org
    DocumentRoot /var/www/dilithion/website

    <Directory /var/www/dilithion/website>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

---

## Customization

### Colors

Edit `style.css` CSS variables (lines 8-20):
```css
:root {
    --primary-color: #6366f1;      /* Indigo */
    --secondary-color: #8b5cf6;    /* Purple */
    --accent-color: #06b6d4;       /* Cyan */
    /* ... */
}
```

### Content

Edit `index.html` directly. Main sections:
- **Hero** (line 28): Main headline and countdown
- **Features** (line 72): Why Dilithion cards
- **Dashboard** (line 126): Live network stats
- **Getting Started** (line 171): Tutorial steps
- **Downloads** (line 251): Platform download links
- **Specifications** (line 295): Technical specs table
- **Footer** (line 353): Links and legal

### Fonts

Current: System fonts (fastest loading)

To use custom fonts, add to `<head>`:
```html
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
```

Update CSS:
```css
body {
    font-family: 'Inter', sans-serif;
}
```

---

## RPC Integration

The website connects to Dilithion's JSON-RPC API to fetch live data.

**RPC Methods Used:**
- `getblockchaininfo` - Block height, difficulty, best block hash
- `getmininginfo` - Network hash rate
- `getblock` - Block timestamp for "last block time"

**CORS Configuration:**

If hosting website and node on different domains, enable CORS in `dilithion-node`:

Add to `src/rpc/server.cpp`:
```cpp
response.setHeader("Access-Control-Allow-Origin", "*");
response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
response.setHeader("Access-Control-Allow-Headers", "Content-Type");
```

---

## Analytics (Optional)

Add Google Analytics to `index.html` before `</head>`:

```html
<!-- Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX');
</script>
```

---

## SEO Optimization

### Meta Tags (Already Included)

```html
<meta name="description" content="Dilithion - The first post-quantum cryptocurrency...">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```

### Add More (Optional)

```html
<meta property="og:title" content="Dilithion - Post-Quantum Cryptocurrency">
<meta property="og:description" content="Fair launch January 1, 2026. CRYSTALS-Dilithium signatures, RandomX mining.">
<meta property="og:image" content="https://dilithion.org/og-image.png">
<meta property="og:url" content="https://dilithion.org">
<meta name="twitter:card" content="summary_large_image">
```

### Sitemap.xml

Create `website/sitemap.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://dilithion.org/</loc>
    <lastmod>2025-10-25</lastmod>
    <priority>1.0</priority>
  </url>
</urlset>
```

---

## SSL Certificate (Production)

Use **Let's Encrypt** for free SSL:

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d dilithion.org -d www.dilithion.org

# Auto-renewal (already configured)
sudo certbot renew --dry-run
```

---

## Performance Optimization

### Minify (Optional)

For production, minify CSS/JS:

```bash
# Install minifiers
npm install -g clean-css-cli uglify-js

# Minify CSS
cleancss -o style.min.css style.css

# Minify JS
uglifyjs script.js -o script.min.js -c -m

# Update index.html to use .min versions
```

### CDN (Optional)

Use Cloudflare CDN for faster global delivery:
1. Sign up at cloudflare.com
2. Add domain
3. Update nameservers
4. Enable caching

---

## Testing Checklist

Before deploying:

- [ ] Countdown timer displays correctly
- [ ] All sections are visible and styled
- [ ] Links work (navigation, downloads, external)
- [ ] Responsive design works on mobile
- [ ] Dashboard connects to RPC (after launch)
- [ ] No console errors in browser
- [ ] Page loads in <2 seconds
- [ ] Works in Chrome, Firefox, Safari, Edge
- [ ] SEO meta tags are correct
- [ ] SSL certificate is valid (production)

---

## Download Links

**Update download links in `index.html` (lines 264, 272, 280):**

Currently set to `#` (placeholder). Replace with:
```html
<!-- GitHub Releases -->
<a href="https://github.com/dilithion/dilithion/releases/download/v1.0.0/dilithion-windows-v1.0.0.zip" class="btn btn-download">Download for Windows</a>

<a href="https://github.com/dilithion/dilithion/releases/download/v1.0.0/dilithion-linux-v1.0.0.tar.gz" class="btn btn-download">Download for Linux</a>

<a href="https://github.com/dilithion/dilithion/releases/download/v1.0.0/dilithion-macos-v1.0.0.dmg" class="btn btn-download">Download for macOS</a>
```

---

## Troubleshooting

### Countdown Not Updating
- Check browser console for JavaScript errors
- Verify `script.js` is loaded
- Check date format in `LAUNCH_DATE`

### Dashboard Shows "—"
- Node must be running on `localhost:9332`
- Check RPC port in node config
- Verify CORS settings (if remote node)
- Check browser console for network errors

### Styles Not Loading
- Verify `style.css` path is correct
- Check for CSS syntax errors
- Clear browser cache (Ctrl+F5)

### Mobile Layout Broken
- Test with browser dev tools (F12 → mobile view)
- Check media queries in `style.css`
- Verify viewport meta tag is present

---

## Future Enhancements

**Month 1-2:**
- Add block explorer link
- Mining pool list
- Exchange listings
- Price ticker (when listed)
- Community links (Discord, Telegram, Reddit)

**Month 3+:**
- Network statistics charts (block time history, hash rate graph)
- Rich list / top addresses
- Transaction volume graph
- Mining calculator
- Wallet balance checker

---

## Support

- **Documentation:** See WHITEPAPER.md
- **GitHub:** https://github.com/dilithion/dilithion
- **Issues:** https://github.com/dilithion/dilithion/issues

---

## License

MIT License - Same as Dilithion cryptocurrency

---

**Created:** October 25, 2025
**Launch Date:** January 1, 2026 00:00:00 UTC
**Status:** Ready for deployment
