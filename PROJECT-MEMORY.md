# DILITHION PROJECT MEMORY
**Last Updated:** November 3, 2025, 08:30 AM
**Status:** Testnet Operational, Ready for Community Announcement

---

## PROJECT PRINCIPLES

**Core Values:**
1. **No Bias to Keep Me Happy** - Provide objective technical analysis and honest assessments, even when they contradict expectations or preferences. Prioritize truth and accuracy over validation.

2. **Keep It Simple** - Favor straightforward, maintainable solutions over complex architectures. Simple systems are easier to audit, debug, and understand.

3. **Robust** - Build for reliability and fault tolerance. All systems must handle failures gracefully with automatic recovery mechanisms.

4. **10/10 and A++ at All Times** - Maintain the highest standards of quality in code, documentation, security, and operations. No shortcuts or "good enough" compromises.

5. **Professional and Safe Decision Making** - Always choose the most professional and safest option when faced with implementation choices. Security and reliability take precedence over convenience or speed.

**Operating Guidelines:**
- **Project Coordinator Role:** Oversee all aspects of development, deployment, and operations with systematic planning and execution
- **Lead Software Engineer Role:** Ensure technical excellence, code quality, and architectural soundness
- **Agent Orchestration:** Create specialized subagents as needed for complex tasks, use planning mode for multi-step operations
- **File Naming:** Use consistent, descriptive naming conventions (UPPERCASE for documentation, lowercase for code, kebab-case for scripts)
- **Documentation:** Maintain comprehensive documentation for all systems, decisions, and procedures

---

## PROJECT OVERVIEW

**Dilithion** is a post-quantum cryptocurrency using CRYSTALS-Dilithium3 signatures and RandomX proof-of-work.

- **Testnet Launch:** November 2, 2025
- **Mainnet Target:** January 1, 2026
- **Current Phase:** Public testnet with seed node operational

---

## INFRASTRUCTURE

### VPS Seed Node
- **IP Address:** 170.64.203.134
- **Port:** 18444 (testnet P2P)
- **RPC Port:** 18332 (localhost only)
- **Provider:** VPS hosting
- **Uptime:** 24/7 with systemd auto-restart
- **Service Name:** `dilithion-testnet.service`
- **Status:** OPERATIONAL

**Key Directories:**
- Node binary: `/root/dilithion/dilithion-node`
- Data directory: `/root/.dilithion-testnet/`
- Stats script: `/root/generate-stats-robust.sh`
- Stats output: `/var/www/html/network-stats.json`
- Startup script: `/root/dilithion-start.sh`

**Stats Generation:**
- Cron job runs every minute: `* * * * * /root/generate-stats-robust.sh`
- HTTP endpoint: http://170.64.203.134/network-stats.json
- CORS enabled (Access-Control-Allow-Origin: *)

### Website (dilithion.org)
- **Primary Domain:** https://dilithion.org
- **Hosting IP:** 198.38.93.43 (separate from VPS)
- **Control Panel:** Web hosting control panel access
- **Dashboard:** Live network statistics display

**Key Files:**
- `/public_html/index.html` - Main website
- `/public_html/script.js` - Dashboard JavaScript
- `/public_html/network-stats.json` - Stats data file
- `/public_html/style.css` - Styling

**Dashboard Configuration:**
```javascript
TESTNET_LAUNCH_DATE = 1762041600000  // Nov 2, 2025
MAINNET_LAUNCH_DATE = 1767225600000  // Jan 1, 2026
STATS_JSON_URL = 'https://dilithion.org/network-stats.json'
UPDATE_INTERVAL = 30000  // 30 seconds
```

### Local Development
- **Working Directory:** C:\Users\will\dilithion
- **Node Binary:** dilithion-node.exe
- **Wallet Tool:** check-wallet-balance.exe
- **Website Files:** C:\Users\will\dilithion\website/
- **VPS Deployment Scripts:** C:\Users\will\dilithion\vps-deployment/

---

## CURRENT STATUS (as of Nov 3, 2025)

### Completed Today:
1. ✅ Deployed VPS seed node (170.64.203.134:18444)
2. ✅ Verified port 18444 accessible from internet
3. ✅ Fixed website dashboard JavaScript (script.js)
4. ✅ Tested dashboard with live data
5. ✅ Comprehensive audit (38/38 tests passing)
6. ✅ Local mining test (mined 2 blocks, 100 DIL)
7. ✅ Responded to Discord user about P2P connection issue

### Pending:
- [ ] Post Discord announcement about testnet operational
- [ ] Set up automated stats sync (VPS → Website)
- [ ] Monitor peer connections over next 24-48 hours

---

## KNOWN ISSUES & SOLUTIONS

### Issue 1: P2P Connection Timing (Non-Critical)
**Symptom:** `Failed to add node 170.64.203.134:18444` on startup

**Root Cause:**
- `--addnode` attempts connection during initialization
- P2P accept/receive threads not fully ready yet
- Initial connection times out

**Resolution:**
- Node's P2P maintenance thread auto-retries every few minutes
- Connection succeeds within 1-2 minutes automatically
- Mining and wallet operations unaffected
- Confirmed via VPS logs showing successful peer connections

**Status:** Known cosmetic issue, will fix in future update

### Issue 2: Separate Website/VPS Servers
**Symptom:** Dashboard stats must be manually updated

**Root Cause:**
- Website hosted at 198.38.93.43
- VPS seed node at 170.64.203.134
- Stats generated on VPS but website on different server

**Current Solution:**
- Manually upload network-stats.json to website control panel
- File location: C:\Users\will\dilithion\test-network-stats.json

**Future Solution:**
- Set up automated sync via cron + scp/API
- OR host stats on VPS with HTTPS to avoid mixed content

**Status:** Manual process working, automation planned

---

## NETWORK PARAMETERS

### Testnet Configuration
- **Network:** testnet
- **Genesis Hash:** 924bdb80469e1185814407147bc763a62425cc400bc902ce37d73ffbc3524475
- **Genesis Time:** 1730000000
- **Difficulty:** 256x easier than mainnet (0x1f060000)
- **Block Reward:** 50 DIL
- **Block Time:** 240 seconds (4 minutes)
- **Halving Interval:** 210,000 blocks
- **Total Supply:** 21 million DIL

### Connection Command
**Windows:**
```bash
dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=4
```

**Linux:**
```bash
./dilithion-node --testnet --addnode=170.64.203.134:18444 --mine --threads=4
```

---

## COMMUNICATION PREFERENCES

- **Tone:** Professional, no emoticons
- **Style:** Technical accuracy, concise
- **Approach:** Systematic problem-solving with verification

---

## RECENT TESTING RESULTS

### Local Mining Test (Nov 3, 2025)
- Started node with 4 threads
- Hash rate: ~75 H/s
- Block 1 mined: Hash 0002fb59... (50 DIL, nonce 8205)
- Block 2 mined: Hash 00002b4e... (50 DIL, nonce 13316)
- Total earned: 100 DIL
- Wallet: DGaSejv8zYXFvi9CWAEZvKgzGjfxNjokuv

### VPS Seed Node Audit Results
**Status:** READY FOR PRODUCTION (HIGH confidence)

**All Systems Passing:**
- Service: Active, running stable for 1+ hours
- Port 18444: Listening on 0.0.0.0, accessible externally
- Stats generation: Updating every minute via cron
- HTTP endpoint: Accessible with proper CORS headers
- Auto-restart: Configured with Restart=always
- Resource usage: Healthy (46% memory, 13% disk)
- Firewall: Properly configured (ports 18444, 80 open)

**Peer Connections Observed:**
- Successfully accepted connections from external IPs
- P2P handshake completing correctly
- Version messages exchanged

---

## KEY FILES TO REMEMBER

### Configuration Files
- `C:\Users\will\dilithion\website\script.js` - Dashboard code
- `C:\Users\will\dilithion\website\index.html` - Main webpage
- `C:\Users\will\dilithion\vps-deployment\deploy-all.sh` - VPS deployment script
- `C:\Users\will\dilithion\vps-deployment\generate-stats-robust.sh` - Stats generator

### Documentation Files
- `C:\Users\will\dilithion\TOMORROW-TODO.md` - Daily task planning
- `C:\Users\will\dilithion\PROJECT-MEMORY.md` - This file
- `C:\Users\will\dilithion\COMPREHENSIVE-AUDIT-REMEDIATION-PLAN.md` - Security audit
- `C:\Users\will\dilithion\website\DEPLOY-DASHBOARD.md` - Dashboard deployment guide

### Temporary Test Files
- `C:\Users\will\dilithion\test-network-stats.json` - Manual stats for dashboard testing
- `C:\Users\will\dilithion\.dilithion-testnet/` - Local node data directory

---

## SSH ACCESS

**VPS Connection:**
```bash
ssh root@170.64.203.134
```

**Common VPS Commands:**
```bash
# Check service status
systemctl status dilithion-testnet

# View logs
journalctl -u dilithion-testnet -n 50

# Check port
ss -tlnp | grep 18444

# View stats
cat /var/www/html/network-stats.json

# Restart service
systemctl restart dilithion-testnet
```

---

## DISCORD COMMUNITY

### Recent User Issues Addressed:
1. **P2P Connection Failure** - Explained timing issue and auto-retry mechanism
2. **Wallet Address Changes** - Privacy feature, not a bug
3. **Findstr Error** - Windows batch script issue, use .exe directly

### Pending Announcements:
- Main testnet operational announcement
- Seed node connection details
- Dashboard launch announcement

---

## NEXT SESSION CHECKLIST

When starting a new session, remember to:
1. Read this PROJECT-MEMORY.md file first
2. Check VPS seed node status: `ssh root@170.64.203.134 "systemctl status dilithion-testnet"`
3. Verify website dashboard at https://dilithion.org
4. Review pending tasks in TOMORROW-TODO.md
5. Check Discord for new community questions

---

## IMPORTANT REMINDERS

### Website Editing Issues
- Web hosting control panel editor **auto-wraps lines** and breaks JavaScript
- **Solution:** Use short, simple const declarations or upload files directly instead of editing in browser
- Always verify deployed version matches local version after upload

### Stats Synchronization
- Stats on VPS update automatically (every minute)
- Stats on website require **manual upload** currently
- Remember: VPS ≠ Website (different servers)

### Git Repository
- Main branch: `main`
- Recent commits focused on security fixes and documentation
- Local repo is now in sync with deployed versions

---

## TROUBLESHOOTING QUICK REFERENCE

**Dashboard showing dashes:**
- Check if network-stats.json uploaded to website
- Hard refresh: Ctrl + Shift + R
- Verify stats file has valid JSON

**Seed node not responding:**
```bash
ssh root@170.64.203.134 "systemctl restart dilithion-testnet"
```

**Stats not updating on VPS:**
```bash
ssh root@170.64.203.134 "/root/generate-stats-robust.sh"
```

**Check if port accessible:**
```bash
powershell.exe -Command "Test-NetConnection -ComputerName 170.64.203.134 -Port 18444"
```

---

## SUCCESS METRICS

### Testnet Launch Goals (Achieved)
- [x] Seed node operational 24/7
- [x] Port accessible from internet
- [x] Dashboard displaying live stats
- [x] Local mining tested successfully
- [x] Community able to connect
- [x] Auto-restart working
- [x] Stats generation automated

### Next Milestones
- [ ] 10+ active peers connected
- [ ] 100+ blocks mined across network
- [ ] Community feedback on testnet
- [ ] Dashboard refinements based on usage
- [ ] Automated stats sync implemented

---

**End of Project Memory**

*This file serves as context for future Claude Code sessions. Read this file at the start of each new session to maintain continuity.*
