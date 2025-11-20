// Quick genesis block miner for Dilithion v1.0.13
// Mines testnet genesis with new difficulty: 0x1f010000

#include <iostream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <primitives/block.h>
#include <crypto/randomx_hash.h>
#include <consensus/pow.h>

using namespace std;
using namespace Dilithion;

int main() {
    cout << "Mining Dilithion Testnet Genesis v1.0.13" << endl;
    cout << "Difficulty: 0x1f010000 (6x harder)" << endl;
    cout << endl;

    // Initialize RandomX
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_for_hashing(rx_key, strlen(rx_key), 0);  // FULL mode

    // Create genesis block
    CBlock genesis;
    genesis.nVersion = 1;
    genesis.hashPrevBlock.SetNull();
    genesis.nTime = 1730000000;
    genesis.nBits = 0x1f010000;
    genesis.nNonce = 0;

    // Coinbase transaction
    string coinbaseMsg = "Dilithion Testnet Genesis v1.0.13 - Bug #28 fixed + 6x difficulty";
    genesis.vtx.assign(coinbaseMsg.begin(), coinbaseMsg.end());

    // Calculate merkle root
    genesis.hashMerkleRoot = genesis.CalculateMerkleRoot();

    // Calculate target
    uint256 target;
    CompactToBig(genesis.nBits, target);

    cout << "Target: " << target.GetHex() << endl;
    cout << "Mining..." << endl;

    // Mine
    uint64_t hashes = 0;
    time_t startTime = time(nullptr);

    while (true) {
        uint256 hash = genesis.GetHash();
        hashes++;

        // Check if valid
        if (HashLessThan(hash, target)) {
            cout << endl;
            cout << "Found valid genesis!" << endl;
            cout << "Nonce: " << genesis.nNonce << endl;
            cout << "Hash: " << hash.GetHex() << endl;
            cout << "Hashes: " << hashes << endl;
            cout << "Time: " << (time(nullptr) - startTime) << " seconds" << endl;
            break;
        }

        // Progress report
        if (hashes % 1000 == 0) {
            time_t elapsed = time(nullptr) - startTime;
            if (elapsed > 0) {
                cout << "\rHashes: " << hashes << " (~" << (hashes / elapsed) << " H/s)" << flush;
            }
        }

        genesis.nNonce++;
    }

    randomx_cleanup();
    return 0;
}
