# RPC Enhancements Implementation Feasibility

## Summary

**Status:** Most enhancements can be implemented now, with varying levels of effort required.

## Current Implementation Status

### ✅ Already Implemented (Partially)

1. **Authentication (username/password)** - **80% Complete**
   - ✅ HTTP Basic Auth parsing (`ExtractAuthHeader`)
   - ✅ Password hashing (PBKDF2-HMAC-SHA3-256)
   - ✅ Authentication infrastructure (`RPCAuth` namespace)
   - ✅ Permission system (`CRPCPermissions`)
   - ⚠️ Needs: Integration into request handling flow
   - **Effort:** Low (1-2 days)

2. **Method filtering/whitelisting** - **90% Complete**
   - ✅ Full permission system (`CRPCPermissions`)
   - ✅ Role-based access control (RBAC)
   - ✅ Method permission mapping
   - ✅ `InitializePermissions()` method exists
   - ⚠️ Needs: Ensure it's called during server startup
   - **Effort:** Very Low (few hours)

### 🟡 Can Be Implemented Now (Medium Effort)

3. **Request logging and auditing** - **30% Complete**
   - ✅ Error logging exists
   - ✅ Client IP tracking (`GetClientIP`)
   - ❌ No structured request logging
   - ❌ No audit trail
   - **Effort:** Medium (3-5 days)
   - **Requirements:**
     - Add logging infrastructure
     - Create audit log format
     - Integrate into request handling

4. **Batch requests** - **40% Complete**
   - ✅ JSON-RPC parsing exists (`ParseRPCRequest`)
   - ✅ Request handling infrastructure
   - ❌ No batch request parsing
   - ❌ No batch response handling
   - **Effort:** Medium (2-3 days)
   - **Requirements:**
     - Parse JSON array of requests
     - Execute each request
     - Combine responses into array

### 🔴 Requires External Libraries (Higher Effort)

5. **TLS/SSL support** - **0% Complete**
   - ❌ No TLS/SSL implementation
   - **Effort:** High (1-2 weeks)
   - **Requirements:**
     - OpenSSL or similar library
     - Certificate management
     - TLS handshake handling
     - HTTPS response building
   - **Dependencies:**
     - OpenSSL (or mbedTLS, LibreSSL)
     - Certificate files

6. **WebSocket support** - **0% Complete**
   - ❌ No WebSocket implementation
   - **Effort:** High (1-2 weeks)
   - **Requirements:**
     - WebSocket library (libwebsockets, uWebSockets, or custom)
     - WebSocket handshake
     - Frame parsing/encoding
     - Subscription management
   - **Dependencies:**
     - WebSocket library
     - Event notification system

## Detailed Implementation Plans

### 1. Complete Authentication Integration

**Current State:**
- Authentication code exists but may not be fully integrated
- `ExtractAuthHeader()` and `BuildHTTPUnauthorized()` methods exist
- Permission system is ready

**What Needs to Be Done:**
1. Ensure `InitializePermissions()` is called during server startup
2. Add authentication check in `HandleClient()` before processing requests
3. Return HTTP 401 for unauthenticated requests
4. Verify permission checks are performed for each method call

**Files to Modify:**
- `src/rpc/server.cpp` - Add auth check in `HandleClient()`
- `src/node/dilithion-node.cpp` - Call `InitializePermissions()` during startup

**Estimated Effort:** 1-2 days

**Testing:**
- Test with valid credentials
- Test with invalid credentials
- Test with missing credentials
- Test permission enforcement

---

### 2. Complete Method Filtering/Whitelisting

**Current State:**
- Full permission system exists
- Method permission mapping is defined
- `CheckMethodPermission()` is available

**What Needs to Be Done:**
1. Verify `InitializePermissions()` is called
2. Ensure permission checks happen in `ExecuteRPC()`
3. Add configuration options for whitelist/blacklist
4. Test with different permission levels

**Files to Modify:**
- `src/rpc/server.cpp` - Ensure permission checks in `ExecuteRPC()`
- `src/util/config.cpp` - Add whitelist/blacklist config options

**Estimated Effort:** Few hours to 1 day

**Testing:**
- Test with readonly role
- Test with wallet role
- Test with admin role
- Test method whitelisting

---

### 3. Request Logging and Auditing

**Current State:**
- Basic error logging exists
- Client IP tracking exists
- No structured request logging

**What Needs to Be Done:**
1. Create `CRPCLogger` class for structured logging
2. Add request logging in `HandleClient()`
3. Add response logging
4. Create audit log format (JSON or structured text)
5. Add configuration options for log levels
6. Implement log rotation

**Files to Create:**
- `src/rpc/logger.h`
- `src/rpc/logger.cpp`

**Files to Modify:**
- `src/rpc/server.cpp` - Add logging calls
- `src/util/config.cpp` - Add logging config options

**Log Format Example:**
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "client_ip": "192.168.1.1",
  "username": "admin",
  "method": "getinfo",
  "params": "...",
  "success": true,
  "duration_ms": 5,
  "error": null
}
```

**Estimated Effort:** 3-5 days

**Testing:**
- Test log file creation
- Test log rotation
- Test different log levels
- Test audit trail completeness

---

### 4. Batch Requests

**Current State:**
- Single request parsing exists
- JSON parsing infrastructure exists
- No batch handling

**What Needs to Be Done:**
1. Detect batch requests (JSON array vs object)
2. Parse array of requests
3. Execute each request
4. Collect responses
5. Combine into response array
6. Handle partial failures

**Files to Modify:**
- `src/rpc/server.cpp` - Add batch request handling in `HandleClient()`
- `src/rpc/json_util.h` - Add batch parsing utilities

**Implementation Example:**
```cpp
// In HandleClient(), after parsing JSON
if (json[0] == '[') {
    // Batch request
    std::vector<RPCRequest> requests = ParseBatchRequest(json);
    std::vector<RPCResponse> responses;
    for (const auto& req : requests) {
        responses.push_back(ExecuteRPC(req));
    }
    response = SerializeBatchResponse(responses);
} else {
    // Single request
    RPCRequest req = ParseRPCRequest(json);
    response = SerializeResponse(ExecuteRPC(req));
}
```

**Estimated Effort:** 2-3 days

**Testing:**
- Test single request (backward compatibility)
- Test batch of 2-3 requests
- Test batch with mixed success/failure
- Test large batches (10+ requests)
- Test batch with invalid requests

---

### 5. TLS/SSL Support

**Current State:**
- No TLS/SSL implementation
- Raw socket handling exists

**What Needs to Be Done:**
1. Add OpenSSL dependency (or mbedTLS)
2. Create TLS context initialization
3. Wrap sockets with SSL context
4. Handle TLS handshake
5. Add certificate management
6. Update HTTP response building for HTTPS
7. Add configuration options

**Dependencies:**
- OpenSSL (or mbedTLS, LibreSSL)
- Certificate files (self-signed or CA-signed)

**Files to Create:**
- `src/rpc/tls.h`
- `src/rpc/tls.cpp`

**Files to Modify:**
- `src/rpc/server.cpp` - Add TLS support in socket handling
- `Makefile` - Add OpenSSL linking
- `src/util/config.cpp` - Add TLS config options

**Configuration Example:**
```conf
# dilithion.conf
rpcssl=1
rpcsslcertificatechainfile=/path/to/cert.pem
rpcsslprivatekeyfile=/path/to/key.pem
rpcsslciphers=HIGH:!aNULL:!MD5
```

**Estimated Effort:** 1-2 weeks

**Testing:**
- Test with self-signed certificate
- Test with CA-signed certificate
- Test TLS version enforcement
- Test cipher suite configuration
- Test certificate validation

---

### 6. WebSocket Support

**Current State:**
- No WebSocket implementation
- HTTP request handling exists

**What Needs to Be Done:**
1. Choose WebSocket library (libwebsockets recommended)
2. Add WebSocket endpoint (separate from HTTP)
3. Implement WebSocket handshake
4. Implement frame parsing/encoding
5. Create subscription system
6. Add event notification infrastructure
7. Integrate with existing RPC methods

**Dependencies:**
- libwebsockets (or uWebSockets, or custom implementation)

**Files to Create:**
- `src/rpc/websocket.h`
- `src/rpc/websocket.cpp`
- `src/rpc/subscriptions.h`
- `src/rpc/subscriptions.cpp`

**Files to Modify:**
- `src/rpc/server.cpp` - Add WebSocket endpoint
- `Makefile` - Add WebSocket library linking
- `src/util/config.cpp` - Add WebSocket config options

**WebSocket Endpoint:**
- `ws://localhost:8332/ws` (or separate port)

**Subscription Example:**
```json
{
  "method": "subscribe",
  "params": ["blocks", "mempool"]
}
```

**Event Notification:**
```json
{
  "type": "block",
  "data": {
    "hash": "...",
    "height": 12345
  }
}
```

**Estimated Effort:** 1-2 weeks

**Testing:**
- Test WebSocket handshake
- Test subscription/unsubscription
- Test event notifications
- Test multiple concurrent connections
- Test reconnection handling

## Implementation Priority

### Phase 1: Quick Wins (1 week)
1. ✅ Complete Authentication Integration (1-2 days)
2. ✅ Complete Method Filtering (few hours)
3. ✅ Request Logging (3-5 days)

### Phase 2: Standard Features (1 week)
4. ✅ Batch Requests (2-3 days)

### Phase 3: Advanced Features (2-3 weeks)
5. ⚠️ TLS/SSL Support (1-2 weeks)
6. ⚠️ WebSocket Support (1-2 weeks)

## Recommendations

1. **Start with Phase 1** - These are high-value, low-effort improvements
2. **Authentication is critical** - Should be completed before production
3. **Batch requests are standard** - JSON-RPC 2.0 feature, should be implemented
4. **TLS/SSL is important** - But can use SSH tunneling as workaround initially
5. **WebSocket is nice-to-have** - Can be deferred if not immediately needed

## Dependencies Summary

### No External Dependencies Required
- ✅ Authentication (complete integration)
- ✅ Method filtering (complete integration)
- ✅ Request logging
- ✅ Batch requests

### External Dependencies Required
- ⚠️ TLS/SSL: OpenSSL (or mbedTLS, LibreSSL)
- ⚠️ WebSocket: libwebsockets (or alternative)

## Conclusion

**4 out of 6 enhancements can be implemented immediately** without external dependencies:
- Authentication (complete integration)
- Method filtering (complete integration)
- Request logging
- Batch requests

**2 enhancements require external libraries:**
- TLS/SSL (OpenSSL)
- WebSocket (libwebsockets)

The quick wins (Phase 1) can be completed in about 1 week and provide significant security and operational improvements.

