# Daily Health Check Guide

**Date:** November 10, 2025
**Script:** `scripts/daily-health-check-2025-11-10.sh`
**Purpose:** Automated monitoring of all production nodes before alpha launch

---

## Overview

This automated health check script monitors all 3 production nodes and reports:
- Node connectivity
- Fuzzer status (running/stopped)
- Crash detection
- Resource monitor logs
- Disk space usage
- Corpus growth

Perfect for daily monitoring during the 48-72 hour baseline testing period before alpha launch.

---

## Quick Start

### Manual Run (Test Now)
```bash
cd /c/Users/will/dilithion
./scripts/daily-health-check-2025-11-10.sh
```

### Automated Daily Runs
```bash
# Run daily at 8am local time
crontab -e

# Add this line:
0 8 * * * cd /c/Users/will/dilithion && ./scripts/daily-health-check-2025-11-10.sh >> health-check.log 2>&1
```

### With Slack Notifications
```bash
# Get webhook from Slack: Settings > Apps > Incoming Webhooks
./scripts/daily-health-check-2025-11-10.sh --slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

---

## What It Checks

### 1. Node Connectivity
- Tests SSH connection to all 3 nodes
- **Status:** Connected / Connection Failed
- **Impact:** CRITICAL if any node unreachable

### 2. Fuzzer Status
- Verifies expected fuzzer is running
- Reports CPU, memory, uptime
- **Status:** Running / Not Running
- **Impact:** CRITICAL if fuzzer stopped

### 3. Crash Detection
- Scans for crash-* files on each node
- Lists recent crashes (last 24h)
- **Status:** No crashes / N crashes found
- **Impact:** ATTENTION_REQUIRED if crashes found

### 4. Resource Monitor Logs
- Checks last 100 log lines for errors/warnings
- Samples recent errors if found
- **Status:** Clean / N errors found
- **Impact:** DEGRADED if errors found

### 5. Disk Space
- Checks root filesystem usage
- **Status:** Healthy (<80%) / Warning (80-90%) / Critical (>90%)
- **Impact:** CRITICAL if >90%

### 6. Corpus Growth
- Counts corpus files per fuzzer
- Verifies corpus directory exists
- **Status:** N files / Empty or not found
- **Impact:** Informational only

---

## Health Status Levels

**HEALTHY** ✅
- All checks passed
- No issues detected
- Ready for alpha launch

**ATTENTION_REQUIRED** ⚠️
- Crashes detected (investigate but not blocking)
- Minor warnings in logs
- Continue monitoring

**DEGRADED** ⚠️
- Monitor errors found
- High disk usage (80-90%)
- Requires investigation

**CRITICAL** 🚨
- Fuzzer not running
- Node unreachable
- Critical disk space (>90%)
- **DO NOT LAUNCH ALPHA**

---

## Output

### Console Output
```
[INFO] ==========================================
[INFO] Dilithion Daily Health Check
[INFO] ==========================================
[INFO] Date: 2025-11-10 12:00:00 UTC

[INFO] Checking connectivity: singapore (188.166.255.63)...
[SUCCESS] ✓ singapore - Connected
[INFO] Checking fuzzer: fuzz_difficulty on singapore...
[SUCCESS] ✓ fuzz_difficulty - Running (CPU: 49.2%, MEM: 578200KB, Time: 291:30)
[INFO] Checking for crashes on singapore...
[SUCCESS] ✓ singapore - No crashes detected
...

[SUCCESS] Health Status: HEALTHY ✓
[INFO] Issues Found: 0
[INFO] Report: /tmp/dilithion-health-20251110-120000.txt
```

### Report File
Detailed report saved to `/tmp/dilithion-health-YYYYMMDD-HHMMSS.txt`:
```
======================================================
Dilithion Testnet - Daily Health Check
======================================================
Date: 2025-11-10 12:00:00 UTC
Report ID: dilithion-health-20251110-120000.txt

--- singapore (188.166.255.63) ---
✓ singapore (188.166.255.63): Connected
✓ fuzz_difficulty on singapore: Running
  - CPU: 49.2%
  - Memory: 578200KB
  - Runtime: 291:30
✓ singapore: No crashes (0 files)
✓ singapore: Monitor logs clean
✓ singapore: Disk usage 45% (healthy)
✓ fuzz_difficulty corpus on singapore: 5 files

...

=== Fuzzing Statistics ===
singapore (fuzz_difficulty): Uptime 291:30
nyc (fuzz_transaction): Uptime 293:18
london (fuzz_sha3): Uptime 292:38

======================================================
Health Status: HEALTHY
Issues Found: 0
Report Location: /tmp/dilithion-health-20251110-120000.txt
======================================================
```

### Slack Notification (Optional)
If `--slack-webhook` provided:
- ✅ Green: HEALTHY
- ⚠️ Yellow: ATTENTION_REQUIRED / DEGRADED
- 🚨 Red: CRITICAL
- Includes summary of issues + report preview

---

## Exit Codes

- **0:** HEALTHY (all checks passed)
- **1:** DEGRADED or ATTENTION_REQUIRED (warnings found)
- **2:** CRITICAL (critical issues found)

Use in scripts:
```bash
if ./scripts/daily-health-check-2025-11-10.sh; then
  echo "All systems healthy"
else
  echo "Issues detected, check report"
fi
```

---

## Recommended Testing Schedule

### Day 1 (Today)
```bash
# Run first baseline check
./scripts/daily-health-check-2025-11-10.sh

# Save baseline report
cp /tmp/dilithion-health-*.txt baseline-day1.txt
```

### Day 2 (Tomorrow)
```bash
# Morning check (8am)
./scripts/daily-health-check-2025-11-10.sh

# Evening check (8pm)
./scripts/daily-health-check-2025-11-10.sh

# Compare: Should see corpus growth, similar uptime
```

### Day 3 (Day After Tomorrow)
```bash
# Final check before alpha decision
./scripts/daily-health-check-2025-11-10.sh

# Review: 48+ hours clean = high confidence for alpha launch
```

---

## Automation Setup

### Option 1: Daily Cron (Recommended)
```bash
# Edit crontab
crontab -e

# Add daily check at 8am (adjust timezone as needed)
0 8 * * * cd /c/Users/will/dilithion && ./scripts/daily-health-check-2025-11-10.sh >> health-check.log 2>&1

# Add evening check at 8pm
0 20 * * * cd /c/Users/will/dilithion && ./scripts/daily-health-check-2025-11-10.sh >> health-check.log 2>&1
```

### Option 2: Systemd Timer (Linux)
```bash
# Create timer unit
sudo tee /etc/systemd/system/dilithion-health.timer <<EOF
[Unit]
Description=Dilithion Health Check Timer

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start
sudo systemctl enable dilithion-health.timer
sudo systemctl start dilithion-health.timer
```

### Option 3: GitHub Actions (CI/CD)
```yaml
# .github/workflows/health-check.yml
name: Daily Health Check
on:
  schedule:
    - cron: '0 8 * * *'
jobs:
  health:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Health Check
        run: ./scripts/daily-health-check-2025-11-10.sh --slack-webhook ${{ secrets.SLACK_WEBHOOK }}
```

---

## Troubleshooting

### Script Hangs on SSH
**Cause:** SSH key not loaded or password prompt
**Fix:**
```bash
# Load SSH key
ssh-add ~/.ssh/id_ed25519

# Or use SSH agent
eval $(ssh-agent)
ssh-add
```

### Permission Denied
**Cause:** Script not executable
**Fix:**
```bash
chmod +x scripts/daily-health-check-2025-11-10.sh
```

### Report File Not Created
**Cause:** /tmp not writable (Windows/WSL)
**Fix:** Modify script to use project directory:
```bash
REPORT_FILE="./health-reports/dilithion-health-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p health-reports
```

### Slack Notifications Not Sending
**Cause:** Invalid webhook URL
**Fix:** Test webhook manually:
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test notification"}' \
  YOUR_SLACK_WEBHOOK_URL
```

---

## Integration with Alpha Launch

### Go/No-Go Decision Criteria

Run final health check before alpha announcement:
```bash
./scripts/daily-health-check-2025-11-10.sh
```

**Decision Matrix:**
- **HEALTHY + 48h+ uptime:** ✅ GO for alpha launch
- **ATTENTION_REQUIRED:** Review crashes, decide case-by-case
- **DEGRADED:** Fix issues first, retest
- **CRITICAL:** ❌ NO-GO, fix critical issues

### Pre-Alpha Checklist
```bash
# Day -3: First baseline
[ ] Run health check, save report
[ ] All nodes HEALTHY
[ ] No crashes detected

# Day -2: 24h stability
[ ] Run health check morning + evening
[ ] Compare with Day -3 baseline
[ ] Corpus growing on all nodes

# Day -1: 48h stability (final check)
[ ] Run health check
[ ] Review all saved reports
[ ] Confirm 48h+ clean operation
[ ] Make GO/NO-GO decision

# Day 0: Alpha launch
[ ] Final health check before announcement
[ ] Post pre-alpha announcement to Discord
[ ] Continue monitoring
```

---

## Next Steps

1. **Test now:**
   ```bash
   ./scripts/daily-health-check-2025-11-10.sh
   ```

2. **Set up automation:**
   ```bash
   crontab -e
   # Add: 0 8,20 * * * cd /c/Users/will/dilithion && ./scripts/daily-health-check-2025-11-10.sh
   ```

3. **Configure Slack (optional):**
   - Get webhook from Slack workspace
   - Add `--slack-webhook URL` to cron job

4. **Monitor for 48-72 hours:**
   - Check reports twice daily
   - Look for consistent HEALTHY status
   - Verify corpus growth
   - Confirm zero crashes

5. **Make alpha decision:**
   - Review final health report
   - Check 48h+ continuous operation
   - Post alpha announcement if clean

---

## Files

**Script:** `scripts/daily-health-check-2025-11-10.sh`
**This Guide:** `docs/DAILY-HEALTH-CHECK-GUIDE-2025-11-10.md`
**Reports:** `/tmp/dilithion-health-*.txt` (or custom location)
**Logs:** `health-check.log` (if using cron)

---

**Status:** Ready for immediate use ✅
**Tested:** Syntax validated, awaiting first run
**Automation:** Ready to configure

Run your first health check now to establish baseline!
