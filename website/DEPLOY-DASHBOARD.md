# Dashboard Deployment Guide

## Step 1: Upload Script to VPS

**On your Windows machine**, upload the script:

```bash
# From C:\Users\will\dilithion\website directory
scp generate-network-stats.sh root@170.64.203.134:/root/
```

## Step 2: Set Up Script on VPS

**SSH into the VPS and run these commands:**

```bash
# Make script executable
chmod +x /root/generate-network-stats.sh

# Create web directory for stats (if using web server)
mkdir -p /var/www/html

# Test the script manually
/root/generate-network-stats.sh

# Check if stats file was created
cat /var/www/html/network-stats.json
```

## Step 3: Set Up Cron Job

**Edit crontab:**

```bash
crontab -e
```

**Add this line (updates every 30 seconds):**

```
* * * * * /root/generate-network-stats.sh
* * * * * sleep 30 && /root/generate-network-stats.sh
```

**Or for simpler 1-minute updates:**

```
* * * * * /root/generate-network-stats.sh
```

**Save and exit** (Ctrl+O, Enter, Ctrl+X in nano)

**Verify cron job:**

```bash
crontab -l
```

## Step 4: Set Up Web Server (if not already running)

**Install nginx (if needed):**

```bash
apt update
apt install -y nginx

# Start nginx
systemctl start nginx
systemctl enable nginx

# Allow HTTP traffic
ufw allow 80/tcp
ufw allow 443/tcp
```

**Configure nginx to serve the stats file:**

```bash
# Edit nginx config
nano /etc/nginx/sites-available/default
```

**Add CORS headers for the stats file:**

```nginx
location /network-stats.json {
    root /var/www/html;
    add_header Access-Control-Allow-Origin *;
    add_header Cache-Control "no-cache, no-store, must-revalidate";
    add_header Pragma "no-cache";
    add_header Expires 0;
}
```

**Reload nginx:**

```bash
nginx -t
systemctl reload nginx
```

## Step 5: Test the Stats Endpoint

**From VPS:**

```bash
curl http://localhost/network-stats.json
```

**From Windows:**

```bash
curl http://170.64.203.134/network-stats.json
```

## Step 6: Upload Updated Website Files

**On your Windows machine:**

```bash
# Upload updated script.js
scp script.js root@170.64.203.134:/var/www/html/

# Or upload entire website directory
scp -r C:\Users\will\dilithion\website/* root@170.64.203.134:/var/www/html/
```

## Step 7: Test Dashboard

Visit: https://dilithion.org

The dashboard should now show live network statistics.

## Monitoring

**View cron logs:**

```bash
tail -f /var/log/syslog | grep CRON
```

**Manual update:**

```bash
/root/generate-network-stats.sh
```

## Troubleshooting

**Stats file not updating:**
- Check cron is running: `systemctl status cron`
- Check script errors: Run manually and check output
- Check RPC is accessible: `curl http://localhost:18332`

**Website shows dashes:**
- Check stats file exists: `cat /var/www/html/network-stats.json`
- Check CORS headers: `curl -I http://170.64.203.134/network-stats.json`
- Check browser console for errors

**RPC not responding:**
- Check node is running: `systemctl status dilithion-testnet`
- Check RPC port: `ss -tlnp | grep 18332`
