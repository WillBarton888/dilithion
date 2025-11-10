# RPC Permission System - User Guide

**Version:** 1.0
**Date:** 2025-11-11
**Audience:** Node operators, system administrators, DevOps engineers

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Role Descriptions](#role-descriptions)
4. [Configuration](#configuration)
5. [User Management](#user-management)
6. [Migration from Legacy Mode](#migration-from-legacy-mode)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Overview

The Dilithion RPC permission system implements **role-based access control (RBAC)** to enforce the principle of least privilege. Instead of giving all authenticated users full administrative access, you can now assign granular permissions based on their actual needs.

### Why Use Permission Roles?

**Before (All users = admin):**
- ❌ Monitoring dashboard credentials → Can stop server and export wallet mnemonic
- ❌ Payment bot credentials → Can encrypt wallet and shut down node
- ❌ No defense against compromised credentials
- ❌ All employees have full system access

**After (Role-based permissions):**
- ✅ Monitoring dashboard → Read-only access (cannot modify anything)
- ✅ Payment bot → Can send transactions but cannot export keys or stop server
- ✅ Defense-in-depth: Compromised readonly creds ≠ full wallet control
- ✅ Employees get minimum permissions needed for their role

### Three Standard Roles

| Role | Permissions | Best For | Risk Level |
|------|-------------|----------|------------|
| **readonly** | Read blockchain/wallet data | Monitoring dashboards, analytics | Low |
| **wallet** | Read + send transactions | Payment bots, trading systems | Medium |
| **admin** | Full access to all methods | System administrators, node operators | Critical |

---

## Quick Start

### Option 1: Legacy Mode (Default - No Changes Needed)

If you **don't create `rpc_permissions.json`**, the system runs in **legacy mode** with a single admin user:

```bash
# Your existing dilithion.conf
rpcuser=admin
rpcpassword=your_strong_password_here
```

**Result:** Works exactly as before - single user with full admin permissions.

**Backwards Compatible:** ✅ Zero breaking changes

### Option 2: Multi-User Mode (Recommended for Production)

**Step 1: Generate First User (Admin)**

```bash
cd /path/to/dilithion
python3 contrib/generate_rpc_user.py admin admin
```

You'll be prompted for a password:
```
Enter password for user 'admin': [hidden]
Confirm password: [hidden]

Add this entry to the 'users' section of rpc_permissions.json:
{
  "admin": {
    "password_hash": "a1b2c3d4e5f6...",
    "salt": "f6e5d4c3b2a1...",
    "role": "admin",
    "comment": "Generated on 2025-11-11T10:00:00"
  }
}
```

**Step 2: Create Configuration File**

```bash
# Copy example config
cp rpc_permissions.json.example rpc_permissions.json

# Edit and add your generated user entry
nano rpc_permissions.json
```

Replace the `_example_admin` entry with your generated JSON.

**Step 3: Set Secure Permissions**

```bash
chmod 600 rpc_permissions.json
```

⚠️ **CRITICAL:** File must be readable only by owner (permissions 0600)

**Step 4: Restart Node**

```bash
# Stop node
./dilithion-cli stop

# Start node (will load rpc_permissions.json)
./dilithiond
```

**Step 5: Test Authentication**

```bash
curl -u admin:YOUR_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}'
```

**Expected:** `{"jsonrpc":"2.0","result":12345,"id":1}`

✅ **Success!** You're now using multi-user permission mode.

---

## Role Descriptions

### Readonly Role (0x000F)

**Permissions:**
- ✅ Read blockchain data (blocks, transactions, chain state)
- ✅ Read wallet balances and addresses
- ✅ Read mempool contents
- ✅ Read mining statistics
- ❌ Cannot send transactions
- ❌ Cannot generate new addresses
- ❌ Cannot modify any state
- ❌ Cannot stop server

**Allowed Methods:**
- `getblockcount`, `getblock`, `getblockhash`, `getbestblockhash`
- `getblockchaininfo`, `getchaintips`, `getrawtransaction`
- `getbalance`, `getaddresses`, `listunspent`, `gettransaction`
- `getmempoolinfo`, `getrawmempool`
- `getmininginfo`
- `getnetworkinfo`, `getpeerinfo`

**Use Cases:**
- **Monitoring Dashboards:** Display blockchain stats, wallet balances
- **Analytics Platforms:** Analyze transaction history, blockchain metrics
- **Alerting Systems:** Monitor for specific events (low balance, etc.)
- **Public Block Explorers:** If you expose RPC (NOT recommended)

**Example: Create Readonly User**

```bash
python3 contrib/generate_rpc_user.py monitor readonly
```

**Test:**
```bash
# Should succeed (read operation)
curl -u monitor:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getbalance","params":[],"id":1}'

# Should fail with HTTP 403 (write operation)
curl -u monitor:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"sendtoaddress","params":["DLXabc",1.0],"id":1}'
```

### Wallet Role (0x003F)

**Permissions:**
- ✅ All readonly permissions
- ✅ Send transactions (`sendtoaddress`, `sendrawtransaction`)
- ✅ Generate new addresses (`getnewaddress`)
- ✅ Sign transactions (`signrawtransaction`)
- ✅ Create/restore HD wallets
- ❌ Cannot export mnemonic (master key)
- ❌ Cannot encrypt wallet
- ❌ Cannot stop server
- ❌ Cannot unlock wallet with passphrase

**Allowed Methods (in addition to readonly):**
- `sendtoaddress`, `sendrawtransaction`
- `getnewaddress`
- `signrawtransaction`
- `createhdwallet`, `restorehdwallet`

**Denied Methods:**
- `encryptwallet`, `walletpassphrase`, `walletpassphrasechange`
- `exportmnemonic`
- `stop`

**Use Cases:**
- **Payment Bots:** Automated e-commerce payment processing
- **Trading Bots:** Cryptocurrency trading automation
- **Point-of-Sale Systems:** Accept payments automatically
- **Withdrawal Services:** Process user withdrawal requests

**Security Benefit:**
If wallet bot credentials are compromised:
- ✅ Attacker can send transactions (limited by available balance)
- ❌ Attacker CANNOT export master key (prevents full wallet theft)
- ❌ Attacker CANNOT stop server (prevents denial of service)
- ❌ Attacker CANNOT encrypt wallet (prevents ransomware-style attack)

**Example: Create Wallet User**

```bash
python3 contrib/generate_rpc_user.py payment_bot wallet
```

**Test:**
```bash
# Should succeed (wallet write operation)
curl -u payment_bot:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getnewaddress","params":[],"id":1}'

# Should fail with HTTP 403 (admin operation)
curl -u payment_bot:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"exportmnemonic","params":[],"id":1}'
```

### Admin Role (0xFFFFFFFF)

**Permissions:**
- ✅ Full access to ALL RPC methods
- ✅ All readonly + wallet permissions
- ✅ Encrypt wallet (`encryptwallet`)
- ✅ Unlock wallet (`walletpassphrase`)
- ✅ Export mnemonic (`exportmnemonic`)
- ✅ Stop server (`stop`)
- ✅ Control mining (`startmining`, `stopmining`)

**Use Cases:**
- **System Administrators:** Full node management
- **Node Operators:** Day-to-day operations
- **Emergency Operations:** Critical security operations

⚠️ **WARNING:** Only assign admin role to **trusted** personnel
- Use multi-factor authentication (future enhancement)
- Rotate credentials regularly
- Monitor audit logs for admin operations
- Never use admin credentials in automated scripts

**Example: Create Admin User**

```bash
python3 contrib/generate_rpc_user.py sysadmin admin
```

**Security Recommendations:**
1. ✅ Use strong password (20+ characters, mixed case, numbers, symbols)
2. ✅ Store credentials in password manager (1Password, LastPass, etc.)
3. ✅ Rotate password every 90 days
4. ✅ Monitor logs for `[RPC-AUDIT]` events with admin role
5. ✅ Consider hardware key (YubiKey) for 2FA (future enhancement)
6. ❌ Never commit credentials to git
7. ❌ Never share admin credentials with multiple people
8. ❌ Never use admin role for automated systems

---

## Configuration

### Configuration File Format

**Location:** `~/.dilithion/rpc_permissions.json` (or custom path)

**Basic Structure:**

```json
{
  "version": 1,
  "users": {
    "username": {
      "password_hash": "hex_string",
      "salt": "hex_string",
      "role": "admin|wallet|readonly",
      "comment": "Optional description"
    }
  }
}
```

### Complete Example

```json
{
  "version": 1,
  "users": {
    "admin": {
      "password_hash": "a1b2c3d4e5f6789012345678901234567890abcdef...",
      "salt": "f6e5d4c3b2a198765432109876543210fedcba...",
      "role": "admin",
      "comment": "System administrator - full access"
    },
    "payment_bot": {
      "password_hash": "123456789abcdef0123456789abcdef0123456789abc...",
      "salt": "fedcba9876543210fedcba9876543210fedcba...",
      "role": "wallet",
      "comment": "E-commerce payment processor"
    },
    "monitor": {
      "password_hash": "abcdef0123456789abcdef0123456789abcdef012345...",
      "salt": "9876543210fedcba9876543210fedcba987654...",
      "role": "readonly",
      "comment": "Monitoring dashboard - read-only"
    }
  }
}
```

### File Permissions

⚠️ **CRITICAL SECURITY REQUIREMENT:**

```bash
# Set permissions to 0600 (owner read/write only)
chmod 600 rpc_permissions.json

# Verify permissions
ls -l rpc_permissions.json
# Should show: -rw------- (600)
```

**Why?** Prevents other users on the system from reading password hashes.

---

## User Management

### Adding a New User

**Step 1: Generate Credentials**

```bash
python3 contrib/generate_rpc_user.py new_user wallet
```

**Step 2: Add to Configuration**

Edit `rpc_permissions.json` and add the generated entry:

```json
{
  "version": 1,
  "users": {
    "existing_user": { ... },
    "new_user": {
      "password_hash": "...",
      "salt": "...",
      "role": "wallet",
      "comment": "Generated on 2025-11-11"
    }
  }
}
```

**Step 3: Restart Node**

```bash
./dilithion-cli stop
./dilithiond
```

**Step 4: Test New User**

```bash
curl -u new_user:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getblockcount","params":[],"id":1}'
```

### Removing a User

**Step 1: Edit Configuration**

Remove user entry from `rpc_permissions.json`:

```json
{
  "version": 1,
  "users": {
    "admin": { ... },
    // "removed_user": { ... }  ← Remove this entire entry
    "monitor": { ... }
  }
}
```

**Step 2: Restart Node**

```bash
./dilithion-cli stop
./dilithiond
```

**Step 3: Verify Removal**

```bash
# Should fail with 401 Unauthorized
curl -u removed_user:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getblockcount","params":[],"id":1}'
```

### Changing User Password

**Step 1: Generate New Credentials**

```bash
python3 contrib/generate_rpc_user.py existing_user wallet
# Enter NEW password when prompted
```

**Step 2: Update Configuration**

Replace the user's `password_hash` and `salt` with new values:

```json
{
  "existing_user": {
    "password_hash": "NEW_HASH_HERE",
    "salt": "NEW_SALT_HERE",
    "role": "wallet",
    "comment": "Password updated 2025-11-11"
  }
}
```

**Step 3: Restart Node**

```bash
./dilithion-cli stop
./dilithiond
```

**Step 4: Test New Password**

```bash
curl -u existing_user:NEW_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getblockcount","params":[],"id":1}'
```

### Changing User Role

**Example: Promote user from readonly to wallet**

**Step 1: Edit Configuration**

```json
{
  "monitor": {
    "password_hash": "...",
    "salt": "...",
    "role": "wallet",  // Changed from "readonly"
    "comment": "Promoted to wallet role 2025-11-11"
  }
}
```

**Step 2: Restart Node**

**Step 3: Verify New Permissions**

```bash
# Now should succeed (was denied before)
curl -u monitor:PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"sendtoaddress","params":["DLXabc",1.0],"id":1}'
```

---

## Migration from Legacy Mode

### Scenario: Currently Using Single RPC User

**Current Setup (dilithion.conf):**
```
rpcuser=admin
rpcpassword=my_secret_password
```

**Migration Steps:**

**Step 1: Generate Admin User**

```bash
python3 contrib/generate_rpc_user.py admin admin
# Use your CURRENT password when prompted
```

**Step 2: Create rpc_permissions.json**

```bash
cp rpc_permissions.json.example rpc_permissions.json
nano rpc_permissions.json
```

Add the generated admin entry.

**Step 3: Add Additional Users (Optional)**

```bash
# Add readonly monitoring user
python3 contrib/generate_rpc_user.py monitor readonly

# Add wallet bot user
python3 contrib/generate_rpc_user.py payment_bot wallet
```

Add these entries to `rpc_permissions.json`.

**Step 4: Set File Permissions**

```bash
chmod 600 rpc_permissions.json
```

**Step 5: Restart Node**

```bash
./dilithion-cli stop
./dilithiond
```

**Step 6: Verify Migration**

```bash
# Check logs for confirmation
tail -f ~/.dilithion/debug.log | grep RPC-PERMISSIONS

# Expected output:
# [RPC-PERMISSIONS] Loaded 3 users from /home/user/.dilithion/rpc_permissions.json
```

**Step 7: Test All Users**

```bash
# Test admin
curl -u admin:ADMIN_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"stop","params":[],"id":1}'

# Test readonly
curl -u monitor:MONITOR_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getbalance","params":[],"id":1}'

# Test wallet
curl -u payment_bot:BOT_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getnewaddress","params":[],"id":1}'
```

✅ **Migration Complete!**

**Rollback (if needed):**
```bash
# Simply remove rpc_permissions.json
rm ~/.dilithion/rpc_permissions.json

# Restart node - will fall back to legacy mode
./dilithion-cli stop
./dilithiond
```

---

## Security Best Practices

### 1. Strong Passwords

✅ **DO:**
- Use 16+ characters
- Mix uppercase, lowercase, numbers, symbols
- Use unique password for each user
- Generate with password manager (1Password, LastPass, KeePass)

❌ **DON'T:**
- Use dictionary words ("password123")
- Reuse passwords from other services
- Use personal information (birthdays, names)
- Use short passwords (<12 characters)

**Example Strong Password:**
```
Tr0ub4dor&3-xK6!mP9#qL2@wN5
```

### 2. File Permissions

✅ **DO:**
```bash
chmod 600 rpc_permissions.json
```

❌ **DON'T:**
```bash
chmod 644 rpc_permissions.json  # ❌ World-readable!
chmod 777 rpc_permissions.json  # ❌ World-writable!
```

### 3. Role Assignment

✅ **DO:**
- Use **readonly** for monitoring dashboards
- Use **wallet** for payment bots and trading systems
- Use **admin** ONLY for trusted system administrators
- Review permissions quarterly

❌ **DON'T:**
- Give admin access to automated systems
- Use admin credentials in scripts
- Share credentials between users
- Give wallet access to monitoring tools

### 4. Network Security

✅ **DO:**
- Use firewall rules (allow only specific IPs)
- Use VPN or SSH tunnels for remote access
- Enable TLS/SSL for RPC (future enhancement)
- Monitor access logs

❌ **DON'T:**
- Expose RPC to public internet
- Allow 0.0.0.0/0 in firewall rules
- Disable authentication
- Ignore failed auth attempts in logs

**Example Firewall Rule (iptables):**
```bash
# Allow RPC only from specific IP
iptables -A INPUT -p tcp --dport 8332 -s 192.168.1.100 -j ACCEPT
iptables -A INPUT -p tcp --dport 8332 -j DROP
```

### 5. Password Rotation

✅ **DO:**
- Rotate admin passwords every 90 days
- Rotate wallet/readonly passwords every 180 days
- Rotate immediately after employee departure
- Document rotation schedule

❌ **DON'T:**
- Never rotate passwords
- Wait months after employee leaves
- Forget which users exist

**Rotation Checklist:**
```markdown
- [ ] Generate new credentials with generate_rpc_user.py
- [ ] Update rpc_permissions.json
- [ ] Restart Dilithion node
- [ ] Test new credentials
- [ ] Update password manager
- [ ] Document change in changelog
- [ ] Notify affected users (if applicable)
```

### 6. Audit Logging

✅ **DO:**
- Monitor `~/.dilithion/debug.log` for authorization failures
- Set up alerts for repeated failed attempts
- Review audit logs weekly
- Investigate all `[RPC-AUTHORIZATION-DENIED]` events

❌ **DON'T:**
- Ignore log files
- Disable logging
- Delete logs prematurely

**Example: Monitor Authorization Failures**
```bash
# Real-time monitoring
tail -f ~/.dilithion/debug.log | grep -E "RPC-AUTHORIZATION-DENIED|RPC-SECURITY"

# Daily report of authorization failures
grep "RPC-AUTHORIZATION-DENIED" ~/.dilithion/debug.log | \
  tail -100 | \
  awk '{print $7, $9, $11}' | \
  sort | uniq -c | sort -rn
```

### 7. Backup & Recovery

✅ **DO:**
- Backup `rpc_permissions.json` securely
- Store backup encrypted (GPG, 7-Zip AES)
- Keep backup in password manager notes
- Test recovery process

❌ **DON'T:**
- Commit to git repository
- Email in plaintext
- Store on shared network drive
- Forget to backup

**Example Backup:**
```bash
# Encrypt backup with GPG
gpg -c rpc_permissions.json
# Creates: rpc_permissions.json.gpg

# Store .gpg file securely
cp rpc_permissions.json.gpg ~/secure_backup/

# Restore when needed
gpg -d rpc_permissions.json.gpg > rpc_permissions.json
chmod 600 rpc_permissions.json
```

---

## Troubleshooting

### Problem: "Insufficient permissions for method 'X'"

**Symptom:**
```json
{
  "error": "Insufficient permissions for method 'sendtoaddress'. Required: 16, User has: 15 (role: readonly)"
}
```

**Cause:** User's role doesn't include required permission.

**Solution:**

1. **Check user's role:**
   ```bash
   grep -A5 "username" rpc_permissions.json
   ```

2. **Determine required role:**
   - `sendtoaddress` requires **wallet** or **admin** role
   - User currently has **readonly** role

3. **Option A: Promote user to wallet role**
   ```json
   {
     "username": {
       "role": "wallet"  // Changed from "readonly"
     }
   }
   ```

4. **Option B: Create new user with wallet role**
   ```bash
   python3 contrib/generate_rpc_user.py payment_user wallet
   ```

5. **Restart node**
   ```bash
   ./dilithion-cli stop && ./dilithiond
   ```

### Problem: "401 Unauthorized"

**Symptom:**
```
HTTP/1.1 401 Unauthorized
```

**Causes:**
1. Wrong username or password
2. User doesn't exist in `rpc_permissions.json`
3. Configuration file not loaded

**Solutions:**

**Check 1: Verify credentials**
```bash
# Check if username exists
grep "username" rpc_permissions.json
```

**Check 2: Verify configuration loaded**
```bash
tail -100 ~/.dilithion/debug.log | grep RPC-PERMISSIONS

# Expected:
# [RPC-PERMISSIONS] Loaded 3 users from ...
```

**Check 3: Test with admin user**
```bash
curl -u admin:ADMIN_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getblockcount","params":[],"id":1}'
```

### Problem: "Config file not found - using legacy mode"

**Symptom:**
```
[RPC-PERMISSIONS] Config file not found: /home/user/.dilithion/rpc_permissions.json - falling back to legacy mode
```

**Cause:** `rpc_permissions.json` doesn't exist or is in wrong location.

**Solution:**

**Check 1: Verify file exists**
```bash
ls -la ~/.dilithion/rpc_permissions.json
```

**Check 2: Create configuration file**
```bash
cp rpc_permissions.json.example ~/.dilithion/rpc_permissions.json
chmod 600 ~/.dilithion/rpc_permissions.json
```

**Check 3: Restart node**
```bash
./dilithion-cli stop && ./dilithiond
```

### Problem: Password changes not taking effect

**Symptom:** Old password still works after updating configuration.

**Cause:** Node hasn't been restarted after configuration change.

**Solution:**
```bash
# Restart node
./dilithion-cli stop
./dilithiond

# Test new password
curl -u username:NEW_PASSWORD http://localhost:8332/ \
     -H "X-Dilithion-RPC: 1" \
     -d '{"method":"getblockcount","params":[],"id":1}'
```

### Problem: "Permission denied" when reading config file

**Symptom:**
```
[RPC-PERMISSIONS] ERROR: Cannot read /home/user/.dilithion/rpc_permissions.json: Permission denied
```

**Cause:** File permissions too restrictive (not readable by node process).

**Solution:**
```bash
# Fix permissions
chmod 600 rpc_permissions.json
chown dilithion:dilithion rpc_permissions.json  # If running as 'dilithion' user
```

---

## FAQ

### Q: Can I use the same password for multiple users?

**A:** Technically yes, but **NOT RECOMMENDED** for security reasons.

If one user's credentials are compromised, all users with the same password are compromised. Use unique passwords for each user.

### Q: How do I know which role to assign?

**A:** Follow the principle of least privilege:

| Use Case | Recommended Role |
|----------|------------------|
| Monitoring dashboard | **readonly** |
| Payment automation | **wallet** |
| Trading bot | **wallet** |
| System administrator | **admin** |
| Emergency operations | **admin** |

### Q: Can I create custom roles with specific permissions?

**A:** Not in the current implementation (v1.0).

Future enhancement will support custom permission combinations. For now, use the three standard roles (readonly, wallet, admin).

### Q: What happens if I delete rpc_permissions.json?

**A:** Node automatically falls back to **legacy mode** (single admin user from dilithion.conf).

This ensures backwards compatibility - you can always revert to single-user mode.

### Q: How do I rotate all passwords at once?

**A:** No built-in bulk operation, but you can script it:

```bash
#!/bin/bash
# rotate_all_passwords.sh

for user in admin payment_bot monitor; do
  echo "Rotating password for $user..."
  python3 contrib/generate_rpc_user.py $user $(get_role $user)
done

echo "Update rpc_permissions.json with new hashes/salts"
echo "Then restart node: ./dilithion-cli stop && ./dilithiond"
```

### Q: Can I use this with Docker/Kubernetes?

**A:** Yes! Mount `rpc_permissions.json` as a secret:

```yaml
# Kubernetes example
apiVersion: v1
kind: Secret
metadata:
  name: rpc-permissions
type: Opaque
stringData:
  rpc_permissions.json: |
    {
      "version": 1,
      "users": { ... }
    }
---
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: dilithion
    volumeMounts:
    - name: rpc-permissions
      mountPath: /home/dilithion/.dilithion/rpc_permissions.json
      subPath: rpc_permissions.json
  volumes:
  - name: rpc-permissions
    secret:
      secretName: rpc-permissions
      defaultMode: 0600
```

### Q: What if I forget the admin password?

**A:** You have two recovery options:

**Option 1: Use legacy mode (temporary)**
```bash
# Remove rpc_permissions.json
mv ~/.dilithion/rpc_permissions.json ~/.dilithion/rpc_permissions.json.backup

# Restart node - will use legacy mode (rpcuser/rpcpassword from dilithion.conf)
./dilithion-cli stop && ./dilithiond

# Now you can access with legacy credentials
curl -u LEGACY_USER:LEGACY_PASSWORD http://localhost:8332/ ...
```

**Option 2: Generate new admin user**
```bash
# Generate new admin
python3 contrib/generate_rpc_user.py admin admin

# Update rpc_permissions.json with new hash/salt
nano ~/.dilithion/rpc_permissions.json

# Restart
./dilithion-cli stop && ./dilithiond
```

### Q: How secure is the password hashing?

**A:** Uses **HMAC-SHA3-256** with cryptographically random 32-byte salt.

- ✅ Industry-standard cryptographic algorithm
- ✅ Each password has unique random salt
- ✅ Constant-time comparison prevents timing attacks
- ⚠️  Current implementation uses single-round hashing

**Future Enhancement:** PBKDF2 with 100,000+ iterations (intentionally slow to prevent brute force).

### Q: Can I see password hashes in logs?

**A:** No. Passwords and hashes are **never logged**.

Only authentication success/failure and role assignments are logged:
```
[RPC-AUDIT] Successful authentication from 192.168.1.100 (user: monitor)
[RPC-PERMISSIONS] User 'monitor' has role: readonly
```

---

## Support

### Getting Help

**Documentation:**
- Permission Model Design: `docs/rpc-permissions-model.md`
- Developer Architecture: `docs/rpc-permissions-architecture.md`
- This User Guide: `docs/rpc-permissions-guide.md`

**Logs:**
```bash
# View RPC permission events
tail -f ~/.dilithion/debug.log | grep -E "RPC-PERMISSIONS|RPC-AUTHORIZATION"
```

**Community:**
- GitHub Issues: https://github.com/dilithion/dilithion/issues
- Discord: #support channel
- Forum: https://forum.dilithion.org

### Reporting Bugs

When reporting permission-related issues, include:
1. Dilithion version (`./dilithiond --version`)
2. Relevant log entries (grep RPC-PERMISSIONS debug.log)
3. Configuration file structure (passwords REMOVED!)
4. Steps to reproduce

**Example Bug Report:**
```markdown
## Bug: Wallet user can call admin methods

**Version:** Dilithion v1.0.0

**Configuration:**
- User "payment_bot" has role: "wallet"
- Attempting method: "stop"

**Expected:** HTTP 403 Forbidden
**Actual:** Method executed successfully

**Logs:**
[RPC-PERMISSIONS] User 'payment_bot' has role: wallet
[RPC-AUDIT] 192.168.1.100 called stop - SUCCESS

**Steps to Reproduce:**
1. Create wallet user
2. Call stop method
3. Observe unexpected success
```

---

## Appendix

### Complete Method-Permission Reference

See `docs/rpc-permissions-model.md` for complete mapping of all 45+ RPC methods to permission requirements.

### Configuration File JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["version", "users"],
  "properties": {
    "version": {
      "type": "number",
      "const": 1
    },
    "users": {
      "type": "object",
      "patternProperties": {
        "^[a-zA-Z0-9_-]+$": {
          "type": "object",
          "required": ["password_hash", "salt", "role"],
          "properties": {
            "password_hash": {
              "type": "string",
              "pattern": "^[0-9a-f]{64}$"
            },
            "salt": {
              "type": "string",
              "pattern": "^[0-9a-f]{64}$"
            },
            "role": {
              "type": "string",
              "enum": ["admin", "wallet", "readonly"]
            },
            "comment": {
              "type": "string"
            }
          }
        }
      }
    }
  }
}
```

---

**Document Version:** 1.0
**Last Updated:** 2025-11-11
**Maintained By:** Dilithion Core Developers
