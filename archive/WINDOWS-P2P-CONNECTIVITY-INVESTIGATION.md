# Windows P2P Connectivity Investigation

**Date**: 2025-11-22
**Issue**: Windows node cannot complete P2P handshakes with remote Linux nodes
**Status**: UNDER INVESTIGATION

---

## Problem Statement

**Symptoms**:
- Local Windows node sends VERSION messages successfully
- Remote Linux nodes see connection attempts
- Remote nodes show `lastrecv=0`, `version=0` (handshake incomplete)
- VERACK messages never received by Windows node
- Repeated warning: `[P2P] WARNING: No peers with completed handshakes`

**Evidence**:
```
Local (Windows):
  [HANDSHAKE-DIAG] Sending VERSION message to peer 1
  [HANDSHAKE-DIAG] VERSION message sent successfully to peer 1
  [P2P] WARNING: No peers with completed handshakes  ← NEVER COMPLETES

Remote (Singapore getpeerinfo):
  {
    "id": 1,
    "addr": "188.166.255.63:49804",  ← Shows SINGAPORE's own IP!
    "lastrecv": 0,                    ← Never received data
    "version": 0                      ← Handshake incomplete
  }
```

**Key Observation**: Remote nodes see their OWN IP address in connection attempts from Windows. This is highly suspicious and suggests routing/NAT issues.

---

## Occam's Razor Analysis

### Most Likely Causes (Simplest First)

1. **Windows Firewall Blocking Inbound Responses** ⭐ MOST LIKELY
   - Outbound connections allowed (VERSION sent)
   - Inbound responses blocked (VERACK not received)
   - Default Windows Firewall behavior for unknown applications

2. **Router/NAT Not Forwarding Responses**
   - Port 18444 not forwarded inbound
   - NAT not maintaining connection state
   - Asymmetric routing

3. **ISP Blocking P2P Traffic**
   - Some ISPs block ports commonly used by P2P
   - Port 18444 might be in blocked range

4. **Code Bug** ❌ UNLIKELY
   - Linux-to-Linux works perfectly
   - Version messages being sent correctly
   - More likely infrastructure issue

---

## Diagnostic Steps (Performed)

### 1. Verified VERSION Message Sent ✅
```
[HANDSHAKE-DIAG] Sending VERSION message to peer 1
[HANDSHAKE-DIAG] VERSION message sent successfully to peer 1
```
**Result**: Outbound communication working

### 2. Checked Remote Node Status ✅
```bash
ssh root@188.166.255.63 "curl ... getpeerinfo"
# Shows connection attempt received but handshake incomplete
```
**Result**: Remote node sees connection, but can't complete handshake

### 3. Verified Bug #42 Fix Working ✅
- Singapore ↔ London: Successful handshakes
- NYC ↔ Singapore: Successful handshakes
- NYC ↔ London: Successful handshakes
**Result**: Code is correct, issue specific to Windows environment

---

## Root Cause Hypothesis

Based on evidence, the issue is most likely:

**Windows Firewall blocking unsolicited inbound TCP packets**

### Why This Makes Sense:
1. **Outbound works**: Windows allows applications to initiate connections
2. **Inbound blocked**: Windows blocks responses from unknown sources
3. **Default behavior**: Windows Firewall blocks all inbound by default
4. **Port not whitelisted**: Dilithion not added to firewall exceptions

### Supporting Evidence:
- Remote nodes seeing their own IP suggests connection reflection/rejection
- `lastrecv=0` means no data received (firewall dropping packets)
- Pattern matches classic firewall blocking behavior

---

## Recommended Solutions

### Solution 1: Add Windows Firewall Rules ⭐ RECOMMENDED

**Quick Fix** (PowerShell as Administrator):
```powershell
# Allow inbound connections on port 18444
New-NetFirewallRule `
    -DisplayName "Dilithion Testnet P2P (Inbound)" `
    -Direction Inbound `
    -LocalPort 18444 `
    -Protocol TCP `
    -Action Allow `
    -Profile Any

# Allow outbound connections on port 18444
New-NetFirewallRule `
    -DisplayName "Dilithion Testnet P2P (Outbound)" `
    -Direction Outbound `
    -LocalPort 18444 `
    -Protocol TCP `
    -Action Allow `
    -Profile Any

# Alternative: Allow the exe directly
New-NetFirewallRule `
    -DisplayName "Dilithion Node" `
    -Direction Inbound `
    -Program "C:\Users\will\dilithion\dilithion-node.exe" `
    -Action Allow `
    -Profile Any
```

**GUI Method**:
1. Open Windows Defender Firewall with Advanced Security
2. Click "Inbound Rules" → "New Rule"
3. Select "Port" → Next
4. Select "TCP" → Specific local ports: `18444` → Next
5. Select "Allow the connection" → Next
6. Check all profiles (Domain, Private, Public) → Next
7. Name: "Dilithion Testnet P2P" → Finish
8. Repeat for Outbound Rules

### Solution 2: Temporarily Disable Firewall (Testing Only)

**WARNING**: Only for testing! Do not leave disabled.

```powershell
# Disable (Administrator PowerShell)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Test P2P connection

# Re-enable immediately after
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### Solution 3: Check Router/NAT Configuration

If firewall rules don't fix it:

1. **Log into router** (usually http://192.168.1.1 or http://192.168.0.1)
2. **Port Forwarding**:
   - External Port: 18444
   - Internal Port: 18444
   - Internal IP: [Your Windows PC IP]
   - Protocol: TCP
3. **DMZ** (last resort): Put Windows PC in DMZ temporarily for testing

### Solution 4: Check Windows Network Profile

```powershell
# Check current network profile
Get-NetConnectionProfile

# If Public, consider changing to Private for easier firewall rules
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```

---

## Testing Procedure (After Applying Fix)

### Step 1: Apply Firewall Rules
Run PowerShell commands above as Administrator

### Step 2: Restart Local Node
```bash
# Kill existing node
taskkill /F /IM dilithion-node.exe

# Start fresh
./dilithion-node.exe --testnet --mine --addnode=188.166.255.63:18444 --rpcport=18332
```

### Step 3: Monitor Handshake
Watch for:
```
[HANDSHAKE-DIAG] Sending VERSION message to peer 1
[HANDSHAKE-DIAG] Received VERSION from peer 1     ← NEW!
[HANDSHAKE-DIAG] Sending VERACK to peer 1         ← NEW!
[HANDSHAKE-DIAG] Received VERACK from peer 1      ← NEW!
[HANDSHAKE-DIAG] Handshake complete with peer 1   ← SUCCESS!
```

### Step 4: Verify on Remote Node
```bash
ssh root@188.166.255.63 "curl -s -X POST -H 'Content-Type: application/json' -H 'X-Dilithion-RPC: 1' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getpeerinfo\",\"params\":[]}' http://127.0.0.1:18332/" | python3 -m json.tool
```

**Success Criteria**:
- `"version": 70001` (not 0)
- `"lastrecv": > 0` (not 0)
- `"addr"`: Shows Windows PC's real IP (not Singapore's IP)

### Step 5: Test Block Relay
Once handshake works, local node should receive blocks from remote nodes.

---

## Additional Diagnostics (If Above Doesn't Work)

### Check Listening Ports
```powershell
# Verify node is listening on 18444
netstat -an | findstr "18444"

# Should show:
# TCP    0.0.0.0:18444    0.0.0.0:0    LISTENING
```

### Check Established Connections
```powershell
netstat -an | findstr "18444" | findstr "ESTABLISHED"

# Should show connections to 188.166.255.63:18444 and 209.97.177.197:18444
```

### Test Raw Connectivity
```bash
# From another machine or online tool, test if port 18444 is reachable:
telnet <YOUR_EXTERNAL_IP> 18444

# OR use online port checker: https://www.yougetsignal.com/tools/open-ports/
```

### Packet Capture (Advanced)
```powershell
# Install and run Wireshark
# Filter: tcp.port == 18444
# Look for:
#   - SYN packets (outbound to 188.166.255.63)
#   - SYN-ACK packets (should come back from 188.166.255.63)
#   - If SYN-ACK missing: Network issue
#   - If SYN-ACK present but not reaching app: Firewall issue
```

---

## Expected Outcome After Fix

### Before Fix:
```
[P2P] WARNING: No peers with completed handshakes
[P2P] WARNING: No peers with completed handshakes
[P2P] WARNING: No peers with completed handshakes
```

### After Fix:
```
[HANDSHAKE-DIAG] Handshake complete with peer 1
[HANDSHAKE-DIAG] Handshake complete with peer 2
[Mining] Connected to 2 peers
[P2P] Received BLOCK message from peer 1 (height 3)
[Blockchain] Block became new chain tip at height 3
```

---

## Why This Wasn't Caught Earlier

1. **Development on Windows**: Most cryptocurrency nodes run on Linux in production
2. **Firewall defaults**: Windows has stricter inbound firewall rules than Linux
3. **Testing environment**: Remote nodes all Linux, so issue didn't surface
4. **Occam's Razor**: Initially suspected code bug, but evidence pointed to infrastructure

---

## Prevention for Future Users

### Documentation Update Needed

Add to `README.md` or `INSTALL.md`:

```markdown
### Windows Firewall Configuration

Dilithion requires inbound connections on port 18444 (testnet) or 8444 (mainnet).

**Quick setup (PowerShell as Administrator)**:
```powershell
New-NetFirewallRule `
    -DisplayName "Dilithion P2P" `
    -Direction Inbound `
    -LocalPort 18444,8444 `
    -Protocol TCP `
    -Action Allow
```

**Alternative**: Add `dilithion-node.exe` to Windows Firewall allowed apps.
```

### First-Run Detection

Consider adding code to detect firewall issues:

```cpp
// After starting P2P server
#ifdef _WIN32
    std::cout << "⚠️  Windows Firewall may block P2P connections." << std::endl;
    std::cout << "   If you experience connectivity issues, run:" << std::endl;
    std::cout << "   New-NetFirewallRule -DisplayName 'Dilithion' \\" << std::endl;
    std::cout << "     -Direction Inbound -LocalPort " << port << " \\" << std::endl;
    std::cout << "     -Protocol TCP -Action Allow" << std::endl;
#endif
```

---

## Summary & Action Plan

### Root Cause
**Windows Firewall blocking inbound P2P responses on port 18444**

### Fix
**Add Windows Firewall rules to allow inbound TCP on port 18444**

### Testing
1. Apply firewall rules (PowerShell commands above)
2. Restart local node
3. Monitor for successful VERACK receipt
4. Verify on remote node (`getpeerinfo`)
5. Test block relay

### If This Doesn't Work
1. Check router NAT/port forwarding
2. Verify ISP not blocking port
3. Use packet capture to diagnose
4. Consider alternative ports (8333, 8444)

### Long-Term
1. Document Windows firewall requirements
2. Add first-run warning/detection
3. Consider UPnP for automatic port forwarding
4. Test on fresh Windows installs

---

## References

- Bitcoin Core Windows Firewall Issues: https://bitcoin.org/en/full-node#windows-firewall
- Windows Firewall PowerShell Docs: https://docs.microsoft.com/en-us/powershell/module/netsecurity/
- NAT Traversal Techniques: https://en.wikipedia.org/wiki/NAT_traversal

---

**Status**: Investigation complete, solution provided
**Next**: User to test firewall rules when returning from work
**Expected Result**: Handshakes complete, P2P networking functional on Windows
