// Global variable stubs for utility binaries
// These binaries (genesis_gen, check-wallet-balance) link against
// modules that reference global variables, but don't actually use them.

#include "node/blockchain_storage.h"
#include "consensus/chain.h"

// Forward declare NodeState (defined in rpc/server.cpp)
struct NodeState;

// Stub definitions to satisfy linker
CBlockchainDB* g_blockchain = nullptr;
CChainState* g_chainstate = nullptr;
NodeState* g_node_state = nullptr;
