# Systemd Best Practices for Cryptocurrency Nodes

Research findings from Bitcoin Core, Ethereum (Geth), and Monero implementations.

## Date: November 15, 2025
## Author: Dilithion Project Team
## Purpose: Production-grade systemd configuration for Dilithion testnet nodes

---

## Research Sources

### Bitcoin Core (bitcoind)
- Official: https://github.com/bitcoin/bitcoin/blob/master/contrib/init/bitcoind.service
- Documentation: https://github.com/bitcoin/bitcoin/blob/master/doc/init.md
- Community guide: https://alexshepherd.me/posts/production-bitcoind-service-on-systemd/

### Ethereum (geth)
- Community configurations: Multiple implementations reviewed
- Post-Merge requirements (JWT authentication, metrics)
- Security considerations for RPC exposure

### Monero (monerod)
- Official: https://github.com/monero-project/monero/blob/master/utils/systemd/monerod.service
- Documentation: https://docs.getmonero.org/running-node/monerod-systemd/
- Configuration guide: https://moneroguides.org/tutorials/00x02-turning-your-monero-node-into-a-service/

---

## Key Best Practices Summary

### 1. Restart Policy
**Industry Standard:**
```ini
Restart=always
RestartSec=10
StartLimitIntervalSec=0
```

**Rationale:**
- `Restart=always`: Node automatically restarts on crash, clean exit, or abnormal exit
- `RestartSec=10`: Wait 10 seconds before restart (prevents rapid restart loops)
- `StartLimitIntervalSec=0`: Disable start rate limiting (node can restart indefinitely)

**Bitcoin Core uses**: `Restart=on-failure` (more conservative)
**Ethereum geth uses**: `Restart=always`
**Monero monerod uses**: `Restart=always`

**Dilithion choice**: `Restart=always` (following Ethereum/Monero - mining nodes need maximum uptime)

### 2. Service Type
**Industry Standard:**
```ini
Type=simple
```

**Rationale:**
- Process stays in foreground
- Systemd monitors the main process directly
- Simpler than Type=forking or Type=notify

**Bitcoin Core uses**: `Type=notify` with systemd integration
**Ethereum geth uses**: `Type=simple`
**Monero monerod uses**: `Type=simple`

**Dilithion choice**: `Type=simple` (our node doesn't have systemd notify support)

### 3. Graceful Shutdown
**Industry Standards:**
```ini
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=300
FinalKillSignal=SIGKILL
```

**Rationale:**
- `KillMode=mixed`: Send SIGTERM to main process, SIGKILL to remaining processes
- `KillSignal=SIGTERM`: Standard graceful shutdown signal
- `TimeoutStopSec=300`: Allow 5 minutes for graceful shutdown (blockchain flush)
- `FinalKillSignal=SIGKILL`: Force kill if timeout exceeded

**Special note**: Ethereum geth originally used SIGINT instead of SIGTERM to prevent immediate shutdown without closing database. Our testing shows Dilithion handles SIGTERM correctly.

**Bitcoin Core**: Default signals (SIGTERM)
**Ethereum geth**: Originally SIGINT, now properly handles SIGTERM
**Monero monerod**: SIGTERM

**Dilithion choice**: SIGTERM with 300 second timeout (blockchain integrity critical)

### 4. User and Permissions
**Industry Standard:**
```ini
User=bitcoin
Group=bitcoin
```

**Rationale:**
- Run as non-root dedicated user
- Limit blast radius of security vulnerabilities
- Proper file ownership for data directories

**Bitcoin Core**: Runs as `bitcoin` user
**Ethereum geth**: Runs as `geth` or `validator` user
**Monero monerod**: Runs as `monero` user

**Dilithion choice**: Running as `root` for testnet (acceptable for test environments, would use dedicated user in production)

### 5. Logging
**Industry Standards:**
```ini
StandardOutput=append:/var/log/service/node.log
StandardError=append:/var/log/service/node.log
SyslogIdentifier=dilithion-node
```

**Rationale:**
- File-based logs for easy debugging
- `append:` prevents log truncation on restart
- SyslogIdentifier allows filtering with journalctl

**Bitcoin Core**: Logs to /var/log/bitcoind/
**Ethereum geth**: Uses journald primarily
**Monero monerod**: Logs to /var/log/monero/monerod.log

**Dilithion choice**: File-based logging to /root/dilithion/node.log (testnet convenience)

### 6. Resource Limits
**Industry Standards:**
```ini
LimitNOFILE=65536
LimitNPROC=4096
```

**Rationale:**
- `LimitNOFILE`: Maximum open files (P2P connections, blockchain files)
- `LimitNPROC`: Maximum processes (thread pool limits)

**Bitcoin Core**: LimitNOFILE=8192
**Ethereum geth**: LimitNOFILE=65536
**Monero monerod**: Default system limits

**Dilithion choice**: LimitNOFILE=65536, LimitNPROC=4096 (generous for P2P and mining threads)

### 7. Security Hardening
**Industry Standards:**
```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
```

**Rationale:**
- `NoNewPrivileges`: Prevents privilege escalation
- `PrivateTmp`: Isolates /tmp directory
- `ProtectSystem`: Makes system directories read-only
- `ProtectHome`: Protects /home directories

**Bitcoin Core**: Uses NoNewPrivileges, PrivateTmp
**Ethereum geth**: Varies by deployment
**Monero monerod**: Minimal hardening in official service

**Dilithion choice**: NoNewPrivileges=true, PrivateTmp=true (balance security vs. compatibility)

### 8. OOM (Out-of-Memory) Protection
**Industry Practice:**
```ini
OOMScoreAdjust=-500
```

**Rationale:**
- Prevents Linux OOM killer from terminating node under memory pressure
- Values -1000 to 1000 (negative = protect, positive = kill first)
- -500 is moderate protection (not critical system service level)

**Bitcoin Core**: Not explicitly set (relies on system defaults)
**Ethereum geth**: Some guides recommend OOMScoreAdjust=-900
**Monero monerod**: Not set

**Dilithion choice**: OOMScoreAdjust=-500 (mining nodes should survive memory pressure)

### 9. Network Dependencies
**Industry Standards:**
```ini
After=network-online.target
Wants=network-online.target
```

**Rationale:**
- `After`: Wait for network to be online before starting
- `Wants`: Soft dependency (node starts even if network target fails)

**Bitcoin Core**: After=network.target
**Ethereum geth**: After=network-online.target
**Monero monerod**: After=network-online.target

**Dilithion choice**: After=network-online.target, Wants=network-online.target (ensure P2P connectivity)

---

## Dilithion-Specific Considerations

### RandomX Initialization
- RandomX dataset building can take 2-15 minutes on first start
- Async initialization allows RPC to start before mining begins
- No special systemd configuration needed (handled by node internally)

### Mining Threads
- Thread count specified via `--threads` flag
- NYC: 2 threads (higher hashrate expected)
- Singapore/London: 1 thread (resource-limited nodes)

### Testnet vs. Mainnet
- Testnet: Running as root acceptable
- Mainnet: MUST use dedicated `dilithion` user

### Blockchain Data Integrity
- CRITICAL: Use SIGTERM not SIGKILL for shutdown
- Allow 300 seconds (5 minutes) for graceful shutdown
- Blockchain database must flush to disk properly

---

## Final Configuration Decisions

Based on research, the Dilithion systemd service will use:

1. **Restart**: `always` with 10 second delay
2. **Type**: `simple` (no systemd notify support)
3. **Kill signals**: SIGTERM with 300 second timeout
4. **User**: `root` (testnet only)
5. **Logging**: File-based append to /root/dilithion/node.log
6. **Resource limits**: NOFILE=65536, NPROC=4096
7. **Security**: NoNewPrivileges=true, PrivateTmp=true
8. **OOM protection**: OOMScoreAdjust=-500
9. **Network**: After=network-online.target

This configuration balances:
- **Uptime**: Aggressive restart policy for mining nodes
- **Safety**: Graceful shutdown for blockchain integrity
- **Performance**: Generous resource limits
- **Security**: Standard hardening without breaking functionality

---

## References

- Bitcoin Core init documentation: https://github.com/bitcoin/bitcoin/blob/master/doc/init.md
- Ethereum systemd guides: Multiple community sources
- Monero node systemd: https://docs.getmonero.org/running-node/monerod-systemd/
- systemd.service man page: https://www.freedesktop.org/software/systemd/man/systemd.service.html
- systemd.exec man page: https://www.freedesktop.org/software/systemd/man/systemd.exec.html

---

Generated with [Claude Code](https://claude.com/claude-code)
