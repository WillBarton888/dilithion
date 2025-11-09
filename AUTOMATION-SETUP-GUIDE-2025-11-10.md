# Automation Setup Guide

**Date:** November 10, 2025
**Component:** Daily Corpus Backups
**Status:** Ready for Deployment

---

## Quick Start

### Local Machine (Current Setup)

If you want to run automated backups from your local machine:

```bash
# Navigate to project directory
cd /c/Users/will/dilithion

# Run automation setup script
./scripts/setup-automation-2025-11-10.sh
```

This will configure a daily cron job to backup corpus files at 00:00 UTC (midnight).

### Production Nodes (Recommended Alternative)

For better reliability, you can also run backups directly from each production node:

#### Option 1: Deploy backup script to one node (e.g., Singapore)

```bash
# Copy backup script to production node
scp scripts/backup-corpus-2025-11-10.sh root@188.166.255.63:/root/

# SSH to node
ssh root@188.166.255.63

# On the production node, set up cron
crontab -e

# Add this line:
0 0 * * * /root/backup-corpus-2025-11-10.sh >> /root/corpus-backup.log 2>&1
```

#### Option 2: Weekly corpus backup (less frequent, lighter load)

```bash
# Run backup once per week (Sunday at 00:00 UTC)
0 0 * * 0 /root/backup-corpus-2025-11-10.sh >> /root/corpus-backup.log 2>&1
```

---

## What Gets Automated

### Daily Corpus Backup
- **Schedule:** 00:00 UTC (midnight) every day
- **Action:** Backs up top 100 corpus files per fuzzer from all 3 nodes
- **Output:** `corpus_backups/YYYY-MM-DD/` directory + tar.gz archive
- **Log:** `corpus-backup.log` in project root
- **Retention:** Automatic pruning of backups older than 30 days

### Files Backed Up Per Run
- fuzz_difficulty (from Singapore node)
- fuzz_transaction (from NYC node)
- fuzz_sha3 (from London node)

**Expected Size:** ~4-15KB per backup (compressed)
**Monthly Storage:** ~500KB - 2MB

---

## Monitoring Automation

### View Backup Logs
```bash
# View last 50 lines
tail -50 corpus-backup.log

# Follow logs in real-time
tail -f corpus-backup.log

# View specific date backup
grep "2025-11-10" corpus-backup.log
```

### Verify Cron Job
```bash
# List all cron jobs
crontab -l

# You should see:
# 0 0 * * * cd /c/Users/will/dilithion && ./scripts/backup-corpus-2025-11-10.sh >> corpus-backup.log 2>&1
```

### Check Backup History
```bash
# List all backups
ls -lh corpus_backups/

# View latest backup manifest
cat corpus_backups/$(ls -1 corpus_backups/ | grep "^20" | sort -r | head -1)/manifest.json
```

---

## Manual Backup (Anytime)

You can always run a backup manually without waiting for the scheduled time:

```bash
cd /c/Users/will/dilithion
./scripts/backup-corpus-2025-11-10.sh
```

---

## Troubleshooting

### Cron Job Not Running

**Check cron service:**
```bash
# On Linux
systemctl status cron

# On WSL
sudo service cron status
sudo service cron start
```

**Verify cron syntax:**
```bash
crontab -l | grep backup-corpus
```

### Backup Fails

**Check SSH connectivity:**
```bash
ssh root@188.166.255.63 "echo 'OK'"
ssh root@134.122.4.164 "echo 'OK'"
ssh root@209.97.177.197 "echo 'OK'"
```

**Check disk space:**
```bash
df -h corpus_backups/
```

**Run in dry-run mode:**
```bash
./scripts/backup-corpus-2025-11-10.sh --dry-run
```

### Logs Not Being Created

**Ensure log directory is writable:**
```bash
ls -ld corpus_backups/
touch corpus-backup.log  # Test write permissions
```

---

## Disabling Automation

To remove the automated backup:

```bash
# Edit crontab
crontab -e

# Delete the line containing:
# 0 0 * * * cd /c/Users/will/dilithion && ./scripts/backup-corpus-2025-11-10.sh

# Or remove all cron jobs:
crontab -r
```

---

## Alternative Automation Options

### Option 1: systemd Timer (Linux)

Create `/etc/systemd/system/dilithion-backup.timer`:
```ini
[Unit]
Description=Daily Dilithion Corpus Backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

### Option 2: GitHub Actions (CI/CD)

Configure `.github/workflows/backup-corpus.yml` to run backups from GitHub infrastructure (see `docs/PHASE-5-COVERAGE-AND-CICD-2025-11-10.md` for details).

---

## Next Steps (Optional)

1. **Weekly pruning automation:**
   ```bash
   # Add to crontab
   0 1 * * 0 /path/to/prune-corpus-backup-2025-11-10.sh >> corpus-prune.log 2>&1
   ```

2. **Slack notifications on backup completion:**
   - Modify `backup-corpus-2025-11-10.sh` to send webhook
   - Add at end: `curl -X POST -H 'Content-type: application/json' --data '{"text":"Corpus backup completed"}' YOUR_SLACK_WEBHOOK`

3. **Cloud storage upload:**
   - Configure AWS S3 or Google Cloud Storage
   - Add: `aws s3 sync corpus_backups/ s3://your-bucket/dilithion-backups/`

---

## Current Status

✅ **Automation Setup Script Created:** `scripts/setup-automation-2025-11-10.sh`
✅ **Backup System Tested:** First backup completed successfully (55 files)
✅ **Documentation Complete:** Usage and troubleshooting guides provided
⏳ **Cron Job:** Ready to configure (run setup script when ready)

---

**Note:** If running on Windows/WSL, ensure WSL cron service is enabled:
```bash
sudo service cron start
```

For production reliability, consider deploying automation directly on one of the Linux production nodes instead of WSL.
