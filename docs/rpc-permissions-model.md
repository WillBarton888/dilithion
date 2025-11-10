# RPC Permission Model Design

**Document Version:** 1.0
**Date:** 2025-11-11
**Status:** Design Specification
**Related:** FIX-014 (RPC-004 - Missing Authorization)

---

## Overview

This document defines the permission model for the Dilithion RPC server's role-based access control (RBAC) system.

### Design Goals

1. **Security:** Enforce least-privilege principle
2. **Simplicity:** Easy to understand and configure
3. **Flexibility:** Support custom permission combinations
4. **Performance:** O(1) permission checking via bitwise operations
5. **Extensibility:** Easy to add new permissions and roles

---

## Permission Bitfield Architecture

### Core Concept

Permissions are represented as a 32-bit unsigned integer bitmask, where each bit represents a specific permission flag. This design enables:

- **Fast checking:** Single bitwise AND operation
- **Compact storage:** 4 bytes per user
- **Flexible combinations:** Any permission subset supported
- **Up to 32 permissions:** Sufficient for current + future needs

### Permission Categories

Permissions are organized into 5 categories by security impact:

#### 1. Read Permissions (Bits 0-3)
**Risk Level:** LOW
**Impact:** Information disclosure only

| Permission | Bit | Value | Description |
|------------|-----|-------|-------------|
| READ_BLOCKCHAIN | 0 | 0x0001 | Read blockchain data (blocks, transactions) |
| READ_WALLET | 1 | 0x0002 | Read wallet balances, addresses, transactions |
| READ_MEMPOOL | 2 | 0x0004 | Read mempool contents |
| READ_MINING | 3 | 0x0008 | Read mining status and statistics |

**Methods Protected:**
- READ_BLOCKCHAIN: `getblockcount`, `getblock`, `getblockhash`, `getbestblockhash`, `getblockchaininfo`, `getchaintips`, `getrawtransaction`, `decoderawtransaction`, `getnetworkinfo`, `getpeerinfo`
- READ_WALLET: `getbalance`, `getaddresses`, `listunspent`, `gettransaction`, `listtransactions`, `gethdwalletinfo`, `listhdaddresses`
- READ_MEMPOOL: `getmempoolinfo`, `getrawmempool`
- READ_MINING: `getmininginfo`

#### 2. Write Permissions (Bits 4-5)
**Risk Level:** MEDIUM-HIGH
**Impact:** State modification, potential fund loss

| Permission | Bit | Value | Description |
|------------|-----|-------|-------------|
| WRITE_WALLET | 4 | 0x0010 | Modify wallet state (send, sign, generate addresses) |
| WRITE_MEMPOOL | 5 | 0x0020 | Inject transactions into mempool |

**Methods Protected:**
- WRITE_WALLET: `getnewaddress`, `sendtoaddress`, `signrawtransaction`, `createhdwallet`, `restorehdwallet`
- WRITE_MEMPOOL: `sendrawtransaction`

#### 3. Control Permissions (Bits 6-7)
**Risk Level:** HIGH
**Impact:** Node operation disruption, resource exhaustion

| Permission | Bit | Value | Description |
|------------|-----|-------|-------------|
| CONTROL_MINING | 6 | 0x0040 | Start/stop mining operations |
| CONTROL_NETWORK | 7 | 0x0080 | Control network connectivity (future: addnode, etc.) |

**Methods Protected:**
- CONTROL_MINING: `startmining`, `stopmining`, `generatetoaddress`
- CONTROL_NETWORK: `addnode` (future implementation)

#### 4. Admin Permissions (Bits 8-9)
**Risk Level:** CRITICAL
**Impact:** Complete system compromise, irreversible damage

| Permission | Bit | Value | Description |
|------------|-----|-------|-------------|
| ADMIN_WALLET | 8 | 0x0100 | Critical wallet operations (encryption, key export) |
| ADMIN_SERVER | 9 | 0x0200 | Server control (shutdown, restart) |

**Methods Protected:**
- ADMIN_WALLET: `encryptwallet`, `walletpassphrase`, `walletlock`, `walletpassphrasechange`, `exportmnemonic`
- ADMIN_SERVER: `stop`

#### 5. Reserved (Bits 10-31)
**Available for future expansion**

Potential future permissions:
- ADMIN_CONFIG (modify server configuration)
- WRITE_BLOCKCHAIN (future: pruning, reindex)
- CONTROL_PEERS (ban/unban peers)
- AUDIT_ACCESS (view audit logs)
- BACKUP_RESTORE (backup/restore operations)

---

## Standard Roles

### Role: Readonly (0x000F)

**Permission Bitmask:** `0x000F` (bits 0-3 set)
**Permissions:**
- READ_BLOCKCHAIN (0x0001)
- READ_WALLET (0x0002)
- READ_MEMPOOL (0x0004)
- READ_MINING (0x0008)

**Use Cases:**
- Monitoring dashboards
- Analytics platforms
- Alerting systems
- Public block explorers (if exposed)

**Allowed Methods:** 18 read-only methods
**Security Impact:** Low (information disclosure only)

**Example Attacks Prevented:**
- Cannot send transactions
- Cannot generate addresses (address enumeration)
- Cannot modify wallet state
- Cannot stop server

### Role: Wallet (0x003F)

**Permission Bitmask:** `0x003F` (bits 0-5 set)
**Permissions:**
- All READONLY permissions (0x000F)
- WRITE_WALLET (0x0010)
- WRITE_MEMPOOL (0x0020)

**Use Cases:**
- Automated payment systems
- Trading bots
- E-commerce integrations
- Point-of-sale systems

**Allowed Methods:** ~30 methods (read + wallet operations)
**Security Impact:** Medium (can send funds but not export keys or stop server)

**Example Attacks Prevented:**
- Cannot stop server (DoS)
- Cannot encrypt wallet (ransomware-style attack)
- Cannot export mnemonic (key theft)
- Cannot control mining (resource exhaustion)

**Damage Limitation:**
If wallet role credentials compromised:
- ✅ Attacker can send transactions (limited by available balance)
- ❌ Attacker CANNOT export master key
- ❌ Attacker CANNOT stop server
- ❌ Attacker CANNOT encrypt wallet

### Role: Admin (0xFFFFFFFF)

**Permission Bitmask:** `0xFFFFFFFF` (all bits set)
**Permissions:** ALL

**Use Cases:**
- System administrators
- Node operators
- Emergency operations
- Initial setup/configuration

**Allowed Methods:** All 45+ methods
**Security Impact:** Critical (full system access)

**Security Recommendations:**
- Use only for administrative tasks
- Never use for automated systems
- Rotate credentials regularly
- Require 2FA for admin operations (future enhancement)
- Audit all admin actions

---

## Permission Checking Algorithm

### Conceptual Algorithm

```
FUNCTION CheckPermission(userPermissions, methodName):
    requiredPermissions = GetMethodPermissions(methodName)

    IF requiredPermissions == 0:
        RETURN TRUE  // Public method (e.g., "help")

    // Check if user has ALL required permissions
    RETURN (userPermissions AND requiredPermissions) == requiredPermissions
```

### Implementation Details

**Time Complexity:** O(1)
**Space Complexity:** O(1)
**CPU Instructions:** ~3-5 instructions (map lookup + bitwise AND + comparison)

**Example:**
```cpp
// User has ROLE_WALLET (0x003F)
uint32_t userPerms = 0x003F;

// Method "sendtoaddress" requires WRITE_WALLET (0x0010)
uint32_t required = 0x0010;

// Check: (0x003F & 0x0010) == 0x0010
//        0x0010 == 0x0010 → TRUE (allowed)

// Method "stop" requires ADMIN_SERVER (0x0200)
uint32_t required = 0x0200;

// Check: (0x003F & 0x0200) == 0x0200
//        0x0000 == 0x0200 → FALSE (denied)
```

---

## Method-Permission Mapping

### Complete Mapping Table

| Method | Permission Required | Bit Value | Rationale |
|--------|-------------------|-----------|-----------|
| **Blockchain Read** | | | |
| getblockcount | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getblock | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getblockhash | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getbestblockhash | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getblockchaininfo | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getchaintips | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getrawtransaction | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| decoderawtransaction | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getnetworkinfo | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| getpeerinfo | READ_BLOCKCHAIN | 0x0001 | Safe read-only |
| **Wallet Read** | | | |
| getbalance | READ_WALLET | 0x0002 | May reveal financial info |
| getaddresses | READ_WALLET | 0x0002 | Privacy concern |
| listunspent | READ_WALLET | 0x0002 | Reveals UTXO set |
| gettransaction | READ_WALLET | 0x0002 | Safe read-only |
| listtransactions | READ_WALLET | 0x0002 | Privacy concern |
| gethdwalletinfo | READ_WALLET | 0x0002 | Safe read-only |
| listhdaddresses | READ_WALLET | 0x0002 | Privacy concern |
| **Mempool Read** | | | |
| getmempoolinfo | READ_MEMPOOL | 0x0004 | Safe read-only |
| getrawmempool | READ_MEMPOOL | 0x0004 | Safe read-only |
| **Mining Read** | | | |
| getmininginfo | READ_MINING | 0x0008 | Safe read-only |
| **Wallet Write** | | | |
| getnewaddress | WRITE_WALLET | 0x0010 | Modifies wallet state |
| sendtoaddress | WRITE_WALLET | 0x0010 | Moves funds (critical) |
| signrawtransaction | WRITE_WALLET | 0x0010 | Uses private keys |
| createhdwallet | WRITE_WALLET | 0x0010 | Creates wallet |
| restorehdwallet | WRITE_WALLET | 0x0010 | Modifies wallet |
| **Mempool Write** | | | |
| sendrawtransaction | WRITE_MEMPOOL | 0x0020 | Injects into mempool |
| **Mining Control** | | | |
| startmining | CONTROL_MINING | 0x0040 | Resource intensive |
| stopmining | CONTROL_MINING | 0x0040 | Affects node operation |
| generatetoaddress | CONTROL_MINING | 0x0040 | Resource intensive |
| **Network Control** | | | |
| addnode | CONTROL_NETWORK | 0x0080 | Affects connectivity |
| **Admin Wallet** | | | |
| encryptwallet | ADMIN_WALLET | 0x0100 | Critical security op |
| walletpassphrase | ADMIN_WALLET | 0x0100 | Unlocks wallet |
| walletlock | ADMIN_WALLET | 0x0100 | Security operation |
| walletpassphrasechange | ADMIN_WALLET | 0x0100 | Security operation |
| exportmnemonic | ADMIN_WALLET | 0x0100 | Exports master key |
| **Admin Server** | | | |
| stop | ADMIN_SERVER | 0x0200 | Stops server (DoS) |
| **Public Methods** | | | |
| help | (none) | 0x0000 | Public information |

**Total Methods:** 45+ methods mapped

### Special Cases

**Public Methods (No Permission Required):**
- `help` - Returns list of available methods
- Future: `getinfo` - Basic node information

**Method Not Found:**
- Unknown methods return permission requirement of `0x0000`
- Treated as public (allowed for all authenticated users)
- Prevents lockout if new methods added

---

## Security Considerations

### Defense in Depth

RBAC is ONE layer of security:

1. **Network Layer:** Firewall rules, VPN, TLS
2. **Authentication Layer:** Strong passwords, rate limiting, lockout
3. **Authorization Layer:** RBAC (this document) ← YOU ARE HERE
4. **Audit Layer:** Comprehensive logging of all actions
5. **Data Layer:** Encrypted wallet, secure storage

### Threat Model

**Attacker Scenarios:**

1. **Compromised Readonly Credentials:**
   - Impact: Information disclosure only
   - Mitigation: RBAC prevents state modification
   - Residual Risk: Low (privacy leak only)

2. **Compromised Wallet Credentials:**
   - Impact: Can send transactions, deplete balance
   - Mitigation: RBAC prevents key export, server control
   - Residual Risk: Medium (limited to available balance)

3. **Compromised Admin Credentials:**
   - Impact: Full system compromise
   - Mitigation: None (admin has all permissions by design)
   - Residual Risk: Critical
   - Recommendation: MFA, hardware keys, strict access control

4. **Privilege Escalation Attempt:**
   - Impact: Readonly/Wallet user attempts admin methods
   - Mitigation: RBAC denies + audit log captures attempt
   - Residual Risk: Low (assuming no implementation bugs)

5. **Configuration Tampering:**
   - Impact: Attacker modifies `rpc_permissions.json`
   - Mitigation: File permissions (0600), integrity monitoring
   - Residual Risk: Low (requires filesystem access)

### Audit Logging Requirements

**Events to Log:**

1. **Authentication Success/Failure:**
   - Timestamp, IP, username, result
   - Example: `[RPC-AUTH] 2025-11-11 10:30:15 192.168.1.100 user 'monitor' - SUCCESS`

2. **Authorization Denial:**
   - Timestamp, IP, username, method, required permissions, user permissions
   - Example: `[RPC-AUTHZ-DENIED] 2025-11-11 10:30:20 192.168.1.100 user 'monitor' (role: readonly) attempted 'sendtoaddress' - DENIED`

3. **Admin Actions:**
   - Timestamp, IP, username, method, parameters (sanitized)
   - Example: `[RPC-ADMIN] 2025-11-11 10:35:00 127.0.0.1 user 'admin' called 'encryptwallet' - SUCCESS`

4. **Suspicious Patterns:**
   - Multiple authorization failures from same IP
   - Repeated attempts to call admin methods with non-admin role
   - Example: `[RPC-SECURITY] 2025-11-11 10:40:00 Suspicious: 10 authorization failures from 192.168.1.100 in 60 seconds`

---

## Extension Points

### Adding New Permissions

**Procedure:**
1. Choose unused bit (10-31)
2. Add to `Permission` enum in `permissions.h`
3. Update role presets if needed
4. Map methods to new permission in `InitializeMethodPermissions()`
5. Update documentation
6. Add unit tests

**Example: Adding BACKUP_RESTORE Permission:**
```cpp
enum class Permission : uint32_t {
    // ... existing permissions ...
    BACKUP_RESTORE = 0x0400,  // Bit 10

    // Updated role presets
    ROLE_ADMIN = 0xFFFFFFFF  // Still includes new permission
};

// Map methods
m_methodPermissions["backupwallet"] = static_cast<uint32_t>(Permission::BACKUP_RESTORE);
m_methodPermissions["restorewallet"] = static_cast<uint32_t>(Permission::BACKUP_RESTORE);
```

### Adding New Roles

**Procedure:**
1. Define role as combination of permissions
2. Add to role presets in `Permission` enum
3. Update `GetRoleName()` function
4. Update documentation
5. Update `generate_rpc_user.py` tool

**Example: Adding MINING_OPERATOR Role:**
```cpp
enum class Permission : uint32_t {
    // ... existing permissions ...

    // New role preset
    ROLE_MINING_OPERATOR = READ_BLOCKCHAIN | READ_MINING | CONTROL_MINING,
    // 0x0001 | 0x0008 | 0x0040 = 0x0049
};

// Update GetRoleName()
std::string GetRoleName(uint32_t permissions) {
    // ... existing checks ...
    else if (permissions == static_cast<uint32_t>(Permission::ROLE_MINING_OPERATOR)) {
        return "mining_operator";
    }
    // ...
}
```

---

## Performance Analysis

### Memory Footprint

**Per User:**
- Username: ~20 bytes (std::string)
- Password salt: 32 bytes
- Password hash: 32 bytes
- Permissions: 4 bytes (uint32_t)
- **Total:** ~88 bytes per user

**100 Users:** ~8.8 KB
**1000 Users:** ~88 KB
**Conclusion:** Negligible memory impact

### CPU Performance

**Permission Check:**
```
1. Map lookup: O(log n) where n = method count (~45)
   - std::map: ~6-7 comparisons
   - ~50 CPU cycles

2. Bitwise AND: O(1)
   - Single CPU instruction
   - ~1 CPU cycle

3. Comparison: O(1)
   - Single CPU instruction
   - ~1 CPU cycle

Total: ~52 CPU cycles ≈ 15-20 nanoseconds @ 3 GHz
```

**Per RPC Request:**
- Authentication: ~100ms (PBKDF2 intentionally slow)
- Authorization: ~20ns (this system)
- **Overhead:** 0.00002% of authentication time

**Conclusion:** Authorization overhead is unmeasurable

---

## Future Enhancements

### 1. Time-Based Permissions
Allow permissions to vary by time of day:
```json
{
  "users": {
    "payment_bot": {
      "role": "wallet",
      "schedule": {
        "allowed_hours": "09:00-17:00",
        "timezone": "UTC"
      }
    }
  }
}
```

### 2. IP-Based Restrictions
Restrict users to specific IP ranges:
```json
{
  "users": {
    "monitor": {
      "role": "readonly",
      "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"]
    }
  }
}
```

### 3. Method-Specific Rate Limits Per Role
Different rate limits for different roles:
```json
{
  "rate_limits": {
    "readonly": {
      "getbalance": 100,
      "sendtoaddress": 0  // Forbidden
    },
    "wallet": {
      "sendtoaddress": 10
    }
  }
}
```

### 4. Multi-Factor Authentication
Require 2FA for admin operations:
```json
{
  "users": {
    "admin": {
      "role": "admin",
      "mfa_required": true,
      "totp_secret": "..."
    }
  }
}
```

---

## Conclusion

This permission model provides:

✅ **Security:** Least-privilege enforcement, defense-in-depth
✅ **Performance:** O(1) checking, negligible overhead
✅ **Flexibility:** Bitfield supports any permission combination
✅ **Extensibility:** 22 unused bits for future permissions
✅ **Simplicity:** 3 standard roles cover 95% of use cases
✅ **Auditability:** All authorization failures logged

**Production Readiness:** Design complete, ready for implementation.

---

**Document Status:** APPROVED for implementation
**Next Step:** Implement `src/rpc/permissions.h` header file (Phase 1.2)
