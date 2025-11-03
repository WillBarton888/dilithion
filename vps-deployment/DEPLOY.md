# Dilithion VPS Deployment - Simple & Robust

## ONE-COMMAND DEPLOYMENT

### From Windows:

```bash
# 1. Upload all files
scp vps-deployment/* root@170.64.203.134:/root/

# 2. SSH into VPS
ssh root@170.64.203.134

# 3. Fix line endings and make executable
dos2unix /root/*.sh
chmod +x /root/*.sh

# 4. Run deployment script
/root/deploy-all.sh
```

**That's it!** Everything is configured automatically.

---

## What This Does:

1. **Cleans up** - Kills old processes, removes lock files
2. **Installs dependencies** - nginx, dos2unix, curl
3. **Sets up systemd service** - With automatic cleanup on startup
4. **Configures stats generation** - With retry logic and error handling
5. **Configures nginx** - With CORS headers for stats endpoint
6. **Starts everything** - Node + stats + web server

---

## Files Created:

- `/root/dilithion-start.sh` - Startup wrapper (handles all cleanup)
- `/root/generate-stats-robust.sh` - Stats generator (with retries)
- `/root/deploy-all.sh` - Deployment script (one-time setup)
- `/etc/systemd/system/dilithion-testnet.service` - systemd service
- `/etc/nginx/sites-available/default` - nginx config

---

## Verify It's Working:

```bash
# Check node status
systemctl status dilithion-testnet

# Check if accepting connections
ss -tlnp | grep 18444

# Check stats file
cat /var/www/html/network-stats.json

# Test from external
curl http://170.64.203.134/network-stats.json
```

---

## How It Prevents Previous Issues:

### Lock File Issues ✅
- **Solution:** Startup wrapper removes lock file before every start
- **Systemd:** Pre-start hook cleans up automatically

### Port Conflicts ✅
- **Solution:** Startup wrapper kills existing processes
- **Systemd:** Pre-start hook ensures clean slate

### RPC Timing ✅
- **Solution:** Stats script retries RPC calls 3 times with 2s delay
- **Fallback:** Creates placeholder stats if RPC unavailable

### Manual Errors ✅
- **Solution:** Single deployment script, no copy/paste needed
- **Automation:** Everything configured automatically

### Crash Recovery ✅
- **Solution:** Systemd restarts service automatically after 10s
- **Cleanup:** Every restart cleans up first

---

## Maintenance Commands:

```bash
# Restart node
systemctl restart dilithion-testnet

# View logs
journalctl -u dilithion-testnet -f

# Manual stats update
/root/generate-stats-robust.sh

# Check cron jobs
crontab -l
```

---

## Troubleshooting:

If anything goes wrong, just re-run:
```bash
/root/deploy-all.sh
```

This will fix everything and restart fresh.

---

## For Tomorrow:

1. Upload updated `script.js` to website
2. Test dashboard at dilithion.org
3. Announce to Discord that seed node is operational

The seed node is now production-ready and bulletproof! 🎯
