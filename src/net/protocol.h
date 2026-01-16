// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_PROTOCOL_H
#define DILITHION_NET_PROTOCOL_H

#include <primitives/block.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace NetProtocol {

/** Network magic bytes - identifies Dilithion network */
static const uint32_t MAINNET_MAGIC = 0xD1714102;  // "DIL" + version
static const uint32_t TESTNET_MAGIC = 0xDAB5BFFA;
static const uint32_t REGTEST_MAGIC = 0xFABFB5DA;

/** Protocol version */
static const int PROTOCOL_VERSION = 70001;
static const int MIN_PEER_PROTO_VERSION = 70001;

/** Default network port */
static const uint16_t DEFAULT_PORT = 8444;
static const uint16_t TESTNET_PORT = 18444;

/** Message size limits */
static const unsigned int MAX_MESSAGE_SIZE = 32 * 1024 * 1024;  // 32 MB
static const unsigned int MAX_HEADERS_SIZE = 2000;
static const unsigned int MAX_INV_SIZE = 50000;

/** Network services */
enum ServiceFlags : uint64_t {
    NODE_NONE = 0,
    NODE_NETWORK = (1 << 0),      // Can serve full blocks
    NODE_BLOOM = (1 << 2),        // Supports bloom filtering
    NODE_WITNESS = (1 << 3),      // Supports witness data
    NODE_NETWORK_LIMITED = (1 << 10),  // Limited history
};

/** Message types */
enum MessageType {
    MSG_VERSION,
    MSG_VERACK,
    MSG_PING,
    MSG_PONG,
    MSG_GETADDR,
    MSG_ADDR,
    MSG_INV,
    MSG_GETDATA,
    MSG_BLOCK,
    MSG_TX,
    MSG_GETHEADERS,
    MSG_HEADERS,
    MSG_GETBLOCKS,
    MSG_MEMPOOL,
    MSG_REJECT,
    MSG_SENDHEADERS,  // BIP 130: Request headers-first block announcements
    MSG_SENDCMPCT,    // BIP 152: Request compact block relay
    MSG_CMPCTBLOCK,   // BIP 152: Compact block message
    MSG_GETBLOCKTXN,  // BIP 152: Request missing transactions
    MSG_BLOCKTXN,     // BIP 152: Missing transactions response
};

/** Inventory vector types */
enum InvType {
    MSG_TX_INV = 1,
    MSG_BLOCK_INV = 2,
    MSG_FILTERED_BLOCK = 3,
    MSG_CMPCT_BLOCK = 4,
};

/** Network message header (24 bytes) */
struct CMessageHeader {
    uint32_t magic;           // Network identifier
    char command[12];         // Command string (null-padded)
    uint32_t payload_size;    // Payload size in bytes
    uint32_t checksum;        // First 4 bytes of SHA256(SHA256(payload))

    CMessageHeader() : magic(0), payload_size(0), checksum(0) {
        memset(command, 0, sizeof(command));
    }

    bool IsValid(uint32_t expected_magic) const {
        // NET-017 FIX: Validate no embedded null bytes in command
        // Commands like "version\0xxxx" should be rejected

        // Check magic and payload size
        if (magic != expected_magic) return false;
        if (payload_size > MAX_MESSAGE_SIZE) return false;

        // Ensure last byte is null-terminated
        if (command[11] != 0) return false;

        // Check for embedded null bytes before the end
        // Find the actual string length
        size_t cmd_len = strnlen(command, 12);

        // If there are any non-null bytes after the first null, reject
        for (size_t i = cmd_len; i < 11; i++) {
            if (command[i] != 0) {
                return false;  // Embedded null followed by non-null data
            }
        }

        return true;
    }

    std::string GetCommand() const {
        return std::string(command, strnlen(command, 12));
    }

    void SetCommand(const std::string& cmd) {
        memset(command, 0, sizeof(command));
        strncpy(command, cmd.c_str(), sizeof(command) - 1);
    }
};

/** Inventory vector */
struct CInv {
    uint32_t type;
    uint256 hash;

    CInv() : type(0) {}
    CInv(uint32_t type_in, const uint256& hash_in) : type(type_in), hash(hash_in) {}

    bool operator==(const CInv& other) const {
        return type == other.type && hash == other.hash;
    }

    bool operator<(const CInv& other) const {
        if (type != other.type) return type < other.type;
        return hash < other.hash;
    }

    std::string ToString() const;
};

/** Network address with timestamp */
struct CAddress {
    uint32_t time;            // Last seen time
    uint64_t services;        // Service flags
    uint8_t ip[16];          // IPv6 address (IPv4 mapped)
    uint16_t port;           // Port number

    CAddress() : time(0), services(NODE_NONE), port(0) {
        memset(ip, 0, sizeof(ip));
    }

    void SetIPv4(uint32_t ipv4) {
        // IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        memset(ip, 0, 10);
        ip[10] = 0xff;
        ip[11] = 0xff;
        // Store in network byte order (big-endian)
        ip[12] = (ipv4 >> 24) & 0xFF;
        ip[13] = (ipv4 >> 16) & 0xFF;
        ip[14] = (ipv4 >> 8) & 0xFF;
        ip[15] = ipv4 & 0xFF;
    }

    // Set IPv4 address from dotted-decimal string (e.g., "192.168.1.1")
    bool SetFromString(const std::string& ipStr) {
        unsigned int a, b, c, d;
        if (sscanf(ipStr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            return false;
        }
        if (a > 255 || b > 255 || c > 255 || d > 255) {
            return false;
        }
        uint32_t ipv4 = (a << 24) | (b << 16) | (c << 8) | d;
        SetIPv4(ipv4);
        return true;
    }

    // BUG #125 FIX: Check if address is null/unset
    bool IsNull() const {
        static const uint8_t zeros[16] = {0};
        return memcmp(ip, zeros, 16) == 0 && port == 0;
    }

    // NET-015 FIX: Validate IP address for P2P networking
    bool IsRoutable() const {
        // Check if IPv4-mapped address
        if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) {
            // Extract IPv4 address
            uint32_t ipv4 = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];

            // Reject loopback (127.0.0.0/8)
            if ((ipv4 & 0xFF000000) == 0x7F000000) return false;

            // Reject private networks
            if ((ipv4 & 0xFF000000) == 0x0A000000) return false;  // 10.0.0.0/8
            if ((ipv4 & 0xFFF00000) == 0xAC100000) return false;  // 172.16.0.0/12
            if ((ipv4 & 0xFFFF0000) == 0xC0A80000) return false;  // 192.168.0.0/16

            // Reject multicast (224.0.0.0/4)
            if ((ipv4 & 0xF0000000) == 0xE0000000) return false;

            // Reject broadcast
            if (ipv4 == 0xFFFFFFFF) return false;

            // Reject 0.0.0.0
            if (ipv4 == 0) return false;

            return true;
        }

        // For pure IPv6, reject loopback (::1)
        static const uint8_t ipv6_loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(ip, ipv6_loopback, 16) == 0) return false;

        // Reject all-zeros
        static const uint8_t ipv6_zero[16] = {0};
        if (memcmp(ip, ipv6_zero, 16) == 0) return false;

        return true;  // Accept other IPv6 addresses
    }

    std::string ToStringIP() const;
    std::string ToString() const;
};

/** Version message data */
struct CVersionMessage {
    int32_t version;          // Protocol version
    uint64_t services;        // Service flags
    int64_t timestamp;        // Current time
    CAddress addr_recv;       // Receiving node's address
    CAddress addr_from;       // Sending node's address
    uint64_t nonce;          // Random nonce
    std::string user_agent;   // Client version string
    int32_t start_height;     // Last block height
    bool relay;              // Relay transactions
    uint256 genesis_hash;     // Genesis block hash (v1.4.2+) - prevents cross-chain connections

    // BUG #50 FIX: Accept blockchain height parameter (Bitcoin Core pattern)
    // Defaults to 0 for backward compatibility, but should be set to actual height
    explicit CVersionMessage(int32_t blockchain_height = 0);
    std::string ToString() const;
};

/** Ping/Pong message */
struct CPingPong {
    uint64_t nonce;

    CPingPong() : nonce(0) {}
    CPingPong(uint64_t nonce_in) : nonce(nonce_in) {}
};

/** GETHEADERS message - request block headers */
struct CGetHeadersMessage {
    std::vector<uint256> locator;  // Block locator hashes (exponential backoff)
    uint256 hashStop;              // Stop hash (0 = get all)

    CGetHeadersMessage() {}
    CGetHeadersMessage(const std::vector<uint256>& locator_in, const uint256& hashStop_in = uint256())
        : locator(locator_in), hashStop(hashStop_in) {}
};

/** HEADERS message - block headers response */
struct CHeadersMessage {
    std::vector<CBlockHeader> headers;  // Block headers (max 2000)

    CHeadersMessage() {}
    explicit CHeadersMessage(const std::vector<CBlockHeader>& headers_in)
        : headers(headers_in) {}
};

/** Message command strings */
inline const char* GetMessageCommand(MessageType type) {
    switch (type) {
        case MSG_VERSION: return "version";
        case MSG_VERACK: return "verack";
        case MSG_PING: return "ping";
        case MSG_PONG: return "pong";
        case MSG_GETADDR: return "getaddr";
        case MSG_ADDR: return "addr";
        case MSG_INV: return "inv";
        case MSG_GETDATA: return "getdata";
        case MSG_BLOCK: return "block";
        case MSG_TX: return "tx";
        case MSG_GETHEADERS: return "getheaders";
        case MSG_HEADERS: return "headers";
        case MSG_GETBLOCKS: return "getblocks";
        case MSG_MEMPOOL: return "mempool";
        case MSG_REJECT: return "reject";
        case MSG_SENDHEADERS: return "sendheaders";
        case MSG_SENDCMPCT: return "sendcmpct";
        case MSG_CMPCTBLOCK: return "cmpctblock";
        case MSG_GETBLOCKTXN: return "getblocktxn";
        case MSG_BLOCKTXN: return "blocktxn";
        default: return "unknown";
    }
}

/** Get current network magic (mainnet by default) */
extern uint32_t g_network_magic;

} // namespace NetProtocol

#endif // DILITHION_NET_PROTOCOL_H
