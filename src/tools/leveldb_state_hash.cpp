// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 Day 5: leveldb_state_hash tool.
//
// Computes a SHA3-256 hash over the entire (sorted) key-value contents of
// a LevelDB database. Two databases with identical contents produce
// identical hashes; any divergence — even a single byte in any key or
// value — produces different hashes.
//
// Used by the Phase 5 V2 byte-equivalence integration test:
//   1. Run node #1 (env-var=0) against regtest; mine N blocks; stop.
//   2. Run node #2 (env-var=1) against regtest; mine N blocks; stop.
//   3. leveldb_state_hash <db1> and <db2>; compare outputs.
//   4. Equal hash → byte-level equivalence proven; PR5.4 unblocked.
//
// Usage: ./leveldb_state_hash <database_path>
// Output: 64-char hex SHA3-256 to stdout, plus key count to stderr.

#include <leveldb/db.h>
#include <leveldb/iterator.h>
#include <leveldb/options.h>

#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <vector>

// Reuse Dilithion's SHA3 — header is small and self-contained.
#include <crypto/sha3.h>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <leveldb_directory>" << std::endl;
        std::cerr << "Outputs SHA3-256 hash of sorted key-value contents." << std::endl;
        return 1;
    }

    const std::string dbPath = argv[1];

    leveldb::Options options;
    options.create_if_missing = false;
    leveldb::DB* db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, dbPath, &db);
    if (!status.ok()) {
        std::cerr << "Failed to open LevelDB at " << dbPath << ": "
                  << status.ToString() << std::endl;
        return 2;
    }

    // SHA3-256 cascading hash: digest_i = SHA3(digest_{i-1} || klen || key
    // || vlen || value). Bounded memory, collision-resistant against
    // shifting bytes between key and value.
    uint8_t digest[32];
    std::memset(digest, 0, sizeof(digest));

    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    uint64_t entry_count = 0;
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        const auto key = it->key();
        const auto value = it->value();

        uint32_t klen = static_cast<uint32_t>(key.size());
        uint32_t vlen = static_cast<uint32_t>(value.size());

        // Build buffer: prev_digest (32) + klen (4) + key + vlen (4) + value
        std::vector<uint8_t> buf;
        buf.reserve(32 + 4 + key.size() + 4 + value.size());
        buf.insert(buf.end(), digest, digest + 32);
        buf.insert(buf.end(),
                   reinterpret_cast<const uint8_t*>(&klen),
                   reinterpret_cast<const uint8_t*>(&klen) + sizeof(klen));
        buf.insert(buf.end(),
                   reinterpret_cast<const uint8_t*>(key.data()),
                   reinterpret_cast<const uint8_t*>(key.data()) + key.size());
        buf.insert(buf.end(),
                   reinterpret_cast<const uint8_t*>(&vlen),
                   reinterpret_cast<const uint8_t*>(&vlen) + sizeof(vlen));
        buf.insert(buf.end(),
                   reinterpret_cast<const uint8_t*>(value.data()),
                   reinterpret_cast<const uint8_t*>(value.data()) + value.size());

        SHA3_256(buf.data(), buf.size(), digest);
        ++entry_count;
    }

    if (!it->status().ok()) {
        std::cerr << "Iterator error: " << it->status().ToString() << std::endl;
        delete it;
        delete db;
        return 3;
    }
    delete it;
    delete db;

    // Output 64-char hex hash to stdout for easy script consumption.
    static const char* hex = "0123456789abcdef";
    char out[65];
    for (int i = 0; i < 32; ++i) {
        out[2*i]     = hex[(digest[i] >> 4) & 0xF];
        out[2*i + 1] = hex[digest[i] & 0xF];
    }
    out[64] = '\0';

    std::cout << out << std::endl;
    std::cerr << "Entries hashed: " << entry_count << std::endl;
    return 0;
}
