# RPC Authentication Configuration Guide

**Date:** October 25, 2025
**Version:** 1.0.0
**Status:** Implemented (TASK-001)

---

## Overview

Dilithion's RPC server now supports HTTP Basic Authentication to prevent unauthorized access. When configured, all RPC requests must include valid credentials.

**Security Features:**
- ✅ HTTP Basic Auth (industry standard)
- ✅ SHA-3-256 password hashing (quantum-resistant)
- ✅ Constant-time comparison (timing attack resistant)
- ✅ Secure random salt generation
- ✅ Thread-safe implementation

---

## Quick Start

### 1. Create Configuration File

Create `dilithion.conf` in your data directory:

```ini
# RPC Server Configuration
rpcuser=myusername
rpcpassword=mySecurePassword123!
rpcport=8332
rpcallowip=127.0.0.1
```

**Important:**
- Choose a strong password (12+ characters, mixed case, numbers, symbols)
- Never share your RPC credentials
- Keep the config file secure (chmod 600 on Unix)

### 2. Start Node with Authentication

```bash
./dilithion-node --conf=dilithion.conf
```

The node will automatically initialize RPC authentication on startup.

### 3. Make Authenticated Requests

**With curl:**
```bash
curl -u myusername:mySecurePassword123! \
     -X POST http://localhost:8332 \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

**Without authentication (will fail with HTTP 401):**
```bash
curl -X POST http://localhost:8332 \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'

# Response: HTTP/1.1 401 Unauthorized
```

---

## Configuration Options

### dilithion.conf Format

```ini
# ============================================================================
# RPC Server Configuration
# ============================================================================

# Username for RPC authentication
# Required if RPC authentication is enabled
rpcuser=myusername

# Password for RPC authentication
# Required if RPC authentication is enabled
# Recommendation: Use 16+ character random password
rpcpassword=mySecurePassword123!

# RPC server port
# Default: 8332 (mainnet), 18332 (testnet)
rpcport=8332

# Allow RPC connections from specific IP
# Default: 127.0.0.1 (localhost only)
# For security, only use localhost unless absolutely necessary
rpcallowip=127.0.0.1

# Bind RPC server to specific interface
# Default: 127.0.0.1 (localhost only)
# WARNING: Binding to 0.0.0.0 exposes RPC to network
rpcbind=127.0.0.1
```

### Security Best Practices

**Password Requirements:**
- ✅ Minimum 12 characters
- ✅ Mix of uppercase and lowercase
- ✅ Include numbers
- ✅ Include special characters
- ✅ Not based on dictionary words
- ❌ Do NOT use: password, dilithion, admin, etc.

**Good passwords:**
```
g7#Kp9$mQ2!vX4@n
Tr0pic@lF!sh2025
Qu@ntumR3sist#42
```

**Bad passwords:**
```
password123
dilithion
admin
letmein
```

### File Permissions

**Unix/Linux/macOS:**
```bash
# Set config file to owner read/write only
chmod 600 dilithion.conf

# Verify permissions
ls -l dilithion.conf
# Should show: -rw------- (600)
```

**Windows:**
```powershell
# Right-click dilithion.conf → Properties → Security
# Remove all users except yourself
# Grant yourself Full Control
```

---

## API Usage Examples

### curl Examples

**Get Balance:**
```bash
curl -u user:pass http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

**Generate New Address:**
```bash
curl -u user:pass http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","params":[],"id":1}'
```

**Start Mining:**
```bash
curl -u user:pass http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"startmining","params":[],"id":1}'
```

### Python Example

```python
import requests
import json

# RPC connection details
rpc_url = "http://localhost:8332"
rpc_user = "myusername"
rpc_password = "mySecurePassword123!"

# Make RPC request
def rpc_call(method, params=[]):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }

    response = requests.post(
        rpc_url,
        auth=(rpc_user, rpc_password),
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload)
    )

    return response.json()

# Example usage
balance = rpc_call("getbalance")
print(f"Balance: {balance['result']} DIL")

address = rpc_call("getnewaddress")
print(f"New address: {address['result']}")
```

### Node.js Example

```javascript
const axios = require('axios');

const rpc_url = 'http://localhost:8332';
const rpc_user = 'myusername';
const rpc_password = 'mySecurePassword123!';

async function rpcCall(method, params = []) {
    try {
        const response = await axios.post(rpc_url, {
            jsonrpc: '2.0',
            method: method,
            params: params,
            id: 1
        }, {
            auth: {
                username: rpc_user,
                password: rpc_password
            },
            headers: {
                'Content-Type': 'application/json'
            }
        });

        return response.data.result;
    } catch (error) {
        if (error.response && error.response.status === 401) {
            console.error('Authentication failed: Invalid credentials');
        } else {
            console.error('RPC call failed:', error.message);
        }
        throw error;
    }
}

// Example usage
(async () => {
    const balance = await rpcCall('getbalance');
    console.log(`Balance: ${balance} DIL`);

    const address = await rpcCall('getnewaddress');
    console.log(`New address: ${address}`);
})();
```

---

## Error Responses

### HTTP 401 Unauthorized

**Causes:**
1. Missing `Authorization` header
2. Malformed `Authorization` header
3. Invalid username
4. Invalid password

**Response:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Dilithion RPC"
Content-Type: application/json

{"error":"Unauthorized - Invalid or missing credentials"}
```

**Solutions:**
- Verify username and password in dilithion.conf
- Check that `-u user:pass` is correct in curl
- Ensure Authorization header is properly formatted

### Example Error Handling

**curl:**
```bash
# Capture HTTP status code
STATUS=$(curl -u user:pass -s -o /dev/null -w "%{http_code}" \
         http://localhost:8332 \
         -X POST \
         -H "Content-Type: application/json" \
         -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}')

if [ $STATUS -eq 401 ]; then
    echo "Authentication failed - check credentials"
elif [ $STATUS -eq 200 ]; then
    echo "Success"
else
    echo "HTTP error: $STATUS"
fi
```

---

## Security Considerations

### ✅ What's Protected

- **All RPC endpoints:** getnewaddress, getbalance, sendtoaddress, etc.
- **Wallet operations:** Cannot be accessed without authentication
- **Mining control:** Cannot start/stop mining without authentication
- **Node control:** Cannot shut down node without authentication

### ⚠️ Limitations

1. **Localhost Only by Default:**
   - RPC server binds to 127.0.0.1 (localhost)
   - Only accessible from same machine
   - **Do NOT expose to network without additional security**

2. **No TLS/HTTPS (yet):**
   - Credentials sent in Base64 (easily decoded)
   - **Only use over localhost or secure VPN**
   - HTTPS support planned for future release

3. **Basic Auth Limitations:**
   - Credentials sent with every request
   - No session management
   - No rate limiting (yet)

### 🔒 Best Practices

**For Personal Use (Localhost):**
- ✅ Use strong password
- ✅ Keep dilithion.conf secure (chmod 600)
- ✅ Don't share credentials
- ✅ Use unique password (not reused elsewhere)

**For Remote Access (NOT RECOMMENDED):**
- ⚠️ Use VPN tunnel
- ⚠️ Use SSH port forwarding
- ⚠️ Add firewall rules
- ⚠️ Monitor access logs
- ❌ **NEVER expose RPC directly to internet**

**SSH Port Forwarding (Recommended for Remote Access):**
```bash
# On your local machine, forward port 8332 through SSH
ssh -L 8332:localhost:8332 user@remote-server

# Now you can connect to localhost:8332 locally
# It will securely tunnel to the remote server
curl -u user:pass http://localhost:8332 ...
```

---

## Troubleshooting

### Authentication Not Required

**Problem:** RPC requests work without credentials

**Cause:** Authentication not configured

**Solution:**
1. Check that `rpcuser` and `rpcpassword` are set in dilithion.conf
2. Restart the node
3. Verify with: `curl http://localhost:8332` (should return 401)

### Authentication Failing

**Problem:** Getting HTTP 401 with correct credentials

**Solutions:**
1. Check username and password in dilithion.conf (no typos)
2. Ensure no spaces around `=` in config: `rpcuser=user` (not `rpcuser = user`)
3. Check password doesn't contain special characters that need escaping
4. Restart node after changing config

### Can't Connect to RPC

**Problem:** Connection refused

**Solutions:**
1. Check node is running: `ps aux | grep dilithion-node`
2. Check RPC port: `netstat -an | grep 8332`
3. Verify rpcbind is correct in config
4. Check firewall rules

---

## Upgrading from Unauthenticated RPC

**If you have existing scripts/tools:**

1. **Update Configuration:**
   - Add `rpcuser` and `rpcpassword` to dilithion.conf

2. **Update Scripts:**
   - Add authentication to all RPC calls
   - Test each script individually

3. **Gradual Migration:**
   - Test in development first
   - Update production scripts one by one
   - Monitor for authentication errors

**Example Script Update:**
```bash
# Before (unauthenticated)
curl http://localhost:8332 -X POST ...

# After (authenticated)
curl -u myuser:mypass http://localhost:8332 -X POST ...
```

---

## Technical Details

### Implementation

**Password Hashing:**
- Algorithm: SHA-3-256 (quantum-resistant)
- Salt: 32 bytes cryptographically secure random
- Hash: SHA3-256(salt || password)

**Comparison:**
- Constant-time comparison
- Prevents timing attacks
- Thread-safe implementation

**Transport:**
- HTTP Basic Auth (RFC 7617)
- Base64 encoding of credentials
- Format: `Authorization: Basic base64(username:password)`

### Source Code

**Files:**
- `src/rpc/auth.h` - Authentication interface
- `src/rpc/auth.cpp` - Implementation
- `src/rpc/server.cpp` - Integration
- `src/test/rpc_auth_tests.cpp` - Comprehensive tests

**API:**
```cpp
// Initialize authentication
RPCAuth::InitializeAuth("username", "password");

// Check if configured
bool configured = RPCAuth::IsAuthConfigured();

// Authenticate request
bool valid = RPCAuth::AuthenticateRequest(username, password);
```

---

## Future Enhancements

**Planned for Future Releases:**

1. **TLS/HTTPS Support**
   - Encrypted transport
   - Certificate-based authentication
   - Mutual TLS (mTLS)

2. **API Key Authentication**
   - Long-lived API keys
   - Per-key permissions
   - Key rotation

3. **Rate Limiting**
   - Prevent brute force attacks
   - Per-IP rate limits
   - Per-user rate limits

4. **Request Signing**
   - Signature-based authentication
   - Replay attack prevention
   - Non-repudiation

5. **Audit Logging**
   - Log all RPC requests
   - Authentication attempts
   - Failed login tracking

---

## References

- **HTTP Basic Auth:** RFC 7617
- **SHA-3:** NIST FIPS 202
- **JSON-RPC 2.0:** https://www.jsonrpc.org/specification
- **Security Best Practices:** https://owasp.org/

---

**Document Version:** 1.0.0
**Last Updated:** October 25, 2025
**Status:** Production-Ready

---

*For additional help, see USER-GUIDE.md or consult the technical documentation.*
