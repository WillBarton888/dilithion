/**
 * Digital DNA RPC Commands
 *
 * Comprehensive RPC interface for Digital DNA identity system.
 *
 * Commands:
 *   getmydigitaldna          - Get this node's Digital DNA identity
 *   registerdigitaldna       - Register this node's identity on-chain
 *   getdigitaldna            - Get Digital DNA for any address
 *   comparedigitaldna        - Compare two identities for similarity
 *   findsimilaridentities    - Find identities similar to given address
 *   listdigitaldna           - List all registered identities
 *   getdigitaldnastats       - Get network-wide identity statistics
 *   collectdigitaldna        - Start/check DNA collection process
 *   validatedigitaldna       - Validate a Digital DNA proof
 *   getlatencyfingerprint    - Get just the latency component
 *   gettimingsignature       - Get just the timing component
 *   getperspectiveproof      - Get just the perspective component
 */

#ifndef DILITHION_DIGITAL_DNA_RPC_H
#define DILITHION_DIGITAL_DNA_RPC_H

#include "digital_dna.h"
#include <string>
#include <functional>
#include <map>
#include <memory>

namespace digital_dna {

// JSON value type (simplified - would use actual JSON library in production)
using JsonValue = std::string;
using JsonObject = std::map<std::string, JsonValue>;

// RPC handler function type
using RpcHandler = std::function<JsonObject(const JsonObject& params)>;

/**
 * RPC command registry
 */
class DigitalDNARpc {
public:
    DigitalDNARpc(DigitalDNARegistry& registry);

    // Register all RPC commands
    void register_commands();

    // Get handler for a command
    RpcHandler get_handler(const std::string& method) const;

    // List all available commands
    std::vector<std::string> list_commands() const;

    // Execute a command
    JsonObject execute(const std::string& method, const JsonObject& params);

    // Set the mining address for DNA collection
    static void set_my_address(const std::array<uint8_t, 20>& address);

    // Get/set the collector pointer (for node integration)
    static DigitalDNACollector* get_collector();
    static void set_collector(std::unique_ptr<DigitalDNACollector> collector);

private:
    DigitalDNARegistry& registry_;
    std::map<std::string, RpcHandler> handlers_;

    // Command handlers
    JsonObject cmd_getmydigitaldna(const JsonObject& params);
    JsonObject cmd_registerdigitaldna(const JsonObject& params);
    JsonObject cmd_getdigitaldna(const JsonObject& params);
    JsonObject cmd_comparedigitaldna(const JsonObject& params);
    JsonObject cmd_findsimilaridentities(const JsonObject& params);
    JsonObject cmd_listdigitaldna(const JsonObject& params);
    JsonObject cmd_getdigitaldnastats(const JsonObject& params);
    JsonObject cmd_collectdigitaldna(const JsonObject& params);
    JsonObject cmd_validatedigitaldna(const JsonObject& params);
    JsonObject cmd_getlatencyfingerprint(const JsonObject& params);
    JsonObject cmd_gettimingsignature(const JsonObject& params);
    JsonObject cmd_getperspectiveproof(const JsonObject& params);

    // Helpers
    std::string address_to_hex(const std::array<uint8_t, 20>& addr) const;
    std::array<uint8_t, 20> hex_to_address(const std::string& hex) const;
    JsonObject dna_to_json(const DigitalDNA& dna) const;
    JsonObject score_to_json(const SimilarityScore& score) const;
    JsonObject error(int code, const std::string& message) const;
};

/**
 * RPC Command Documentation
 */
struct RpcCommandInfo {
    const char* name;
    const char* description;
    const char* params;
    const char* returns;
    const char* example;
};

// Get documentation for all commands
std::vector<RpcCommandInfo> get_rpc_help();

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_RPC_H
