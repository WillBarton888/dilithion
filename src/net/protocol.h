// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_PROTOCOL_H
#define DILITHION_NET_PROTOCOL_H

#include <primitives/block.h>
#include <cstdint>
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
        return magic == expected_magic &&
               payload_size <= MAX_MESSAGE_SIZE &&
               command[11] == 0;  // Ensure null-terminated
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

    CVersionMessage();
    std::string ToString() const;
};

/** Ping/Pong message */
struct CPingPong {
    uint64_t nonce;

    CPingPong() : nonce(0) {}
    CPingPong(uint64_t nonce_in) : nonce(nonce_in) {}
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
        default: return "unknown";
    }
}

/** Get current network magic (mainnet by default) */
extern uint32_t g_network_magic;

} // namespace NetProtocol

#endif // DILITHION_NET_PROTOCOL_H
