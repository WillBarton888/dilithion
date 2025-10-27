// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/blockchain_storage.h>
#include <leveldb/write_batch.h>
#include <leveldb/options.h>
#include <cstring>
#include <iostream>

CBlockchainDB::CBlockchainDB() : db(nullptr) {}

CBlockchainDB::~CBlockchainDB() {
    Close();
}

bool CBlockchainDB::Open(const std::string& path, bool create_if_missing) {
    std::lock_guard<std::mutex> lock(cs_db);

    if (db != nullptr) {
        return true;  // Already open
    }

    datadir = path;

    leveldb::Options options;
    options.create_if_missing = create_if_missing;
    options.compression = leveldb::kSnappyCompression;

    leveldb::DB* raw_db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &raw_db);

    if (!status.ok()) {
        std::cerr << "Failed to open database: " << status.ToString() << std::endl;
        return false;
    }

    db.reset(raw_db);
    return true;
}

void CBlockchainDB::Close() {
    std::lock_guard<std::mutex> lock(cs_db);
    db.reset();
}

bool CBlockchainDB::IsOpen() const {
    std::lock_guard<std::mutex> lock(cs_db);
    return db != nullptr;
}

bool CBlockchainDB::WriteBlock(const uint256& hash, const CBlock& block) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();

    // Serialize block - binary format with versioning and integrity checks
    // Format: [VERSION][DATA_LENGTH][DATA][CHECKSUM]
    std::string value;
    value.reserve(512);  // Reserve space for typical block

    // Version 1 format marker
    const uint32_t SERIALIZATION_VERSION = 1;
    value.append(reinterpret_cast<const char*>(&SERIALIZATION_VERSION), sizeof(SERIALIZATION_VERSION));

    // Build data section
    std::string data;
    data.reserve(400);

    auto append_int32 = [&data](int32_t v) {
        data.append(reinterpret_cast<const char*>(&v), sizeof(v));
    };
    auto append_uint32 = [&data](uint32_t v) {
        data.append(reinterpret_cast<const char*>(&v), sizeof(v));
    };
    auto append_uint256 = [&data](const uint256& v) {
        data.append(reinterpret_cast<const char*>(v.begin()), 32);
    };

    // Serialize block header
    append_int32(block.nVersion);
    append_uint256(block.hashPrevBlock);
    append_uint256(block.hashMerkleRoot);
    append_uint32(block.nTime);
    append_uint32(block.nBits);
    append_uint32(block.nNonce);

    // Serialize transaction data
    uint32_t vtx_size = static_cast<uint32_t>(block.vtx.size());
    append_uint32(vtx_size);
    if (vtx_size > 0) {
        data.append(reinterpret_cast<const char*>(block.vtx.data()), vtx_size);
    }

    // Write data length
    uint32_t data_length = static_cast<uint32_t>(data.size());
    value.append(reinterpret_cast<const char*>(&data_length), sizeof(data_length));

    // Write data
    value.append(data);

    // Calculate and append checksum
    uint32_t checksum = 0;
    for (unsigned char c : data) {
        checksum += c;
    }
    value.append(reinterpret_cast<const char*>(&checksum), sizeof(checksum));

    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

bool CBlockchainDB::ReadBlock(const uint256& hash, CBlock& block) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);

    if (!status.ok()) {
        return false;
    }

    // Check minimum size for versioned format
    const size_t MIN_SIZE = sizeof(uint32_t) * 3;  // version + length + checksum
    if (value.size() < MIN_SIZE) {
        std::cerr << "[ERROR] ReadBlock: Data too small (" << value.size() << " bytes)" << std::endl;
        return false;
    }

    const char* ptr = value.data();
    size_t offset = 0;

    // Read and validate version
    uint32_t version;
    std::memcpy(&version, ptr + offset, sizeof(version));
    offset += sizeof(version);

    if (version != 1) {
        std::cerr << "[ERROR] ReadBlock: Unsupported version " << version << std::endl;
        return false;
    }

    // Read data length
    uint32_t data_length;
    std::memcpy(&data_length, ptr + offset, sizeof(data_length));
    offset += sizeof(data_length);

    // Validate data length
    const size_t expected_total_size = sizeof(version) + sizeof(data_length) + data_length + sizeof(uint32_t);
    if (value.size() != expected_total_size) {
        std::cerr << "[ERROR] ReadBlock: Size mismatch. Expected " << expected_total_size
                  << ", got " << value.size() << std::endl;
        return false;
    }

    // Extract data section
    if (offset + data_length > value.size()) {
        std::cerr << "[ERROR] ReadBlock: Data length exceeds buffer" << std::endl;
        return false;
    }

    std::string data = value.substr(offset, data_length);
    offset += data_length;

    // Read and verify checksum
    uint32_t stored_checksum;
    std::memcpy(&stored_checksum, ptr + offset, sizeof(stored_checksum));

    uint32_t calculated_checksum = 0;
    for (unsigned char c : data) {
        calculated_checksum += c;
    }

    if (stored_checksum != calculated_checksum) {
        std::cerr << "[ERROR] ReadBlock: Checksum mismatch. Stored: " << stored_checksum
                  << ", Calculated: " << calculated_checksum << std::endl;
        return false;
    }

    // Deserialize data with bounds checking
    const char* data_ptr = data.data();
    size_t data_offset = 0;

    auto read_int32 = [&data_ptr, &data_offset, &data]() -> int32_t {
        if (data_offset + sizeof(int32_t) > data.size()) return 0;
        int32_t v;
        std::memcpy(&v, data_ptr + data_offset, sizeof(v));
        data_offset += sizeof(v);
        return v;
    };
    auto read_uint32 = [&data_ptr, &data_offset, &data]() -> uint32_t {
        if (data_offset + sizeof(uint32_t) > data.size()) return 0;
        uint32_t v;
        std::memcpy(&v, data_ptr + data_offset, sizeof(v));
        data_offset += sizeof(v);
        return v;
    };
    auto read_uint256 = [&data_ptr, &data_offset, &data](uint256& v) -> bool {
        if (data_offset + 32 > data.size()) return false;
        std::memcpy(v.begin(), data_ptr + data_offset, 32);
        data_offset += 32;
        return true;
    };

    // Deserialize block header
    block.nVersion = read_int32();
    if (!read_uint256(block.hashPrevBlock)) {
        std::cerr << "[ERROR] ReadBlock: Failed to read hashPrevBlock" << std::endl;
        return false;
    }
    if (!read_uint256(block.hashMerkleRoot)) {
        std::cerr << "[ERROR] ReadBlock: Failed to read hashMerkleRoot" << std::endl;
        return false;
    }
    block.nTime = read_uint32();
    block.nBits = read_uint32();
    block.nNonce = read_uint32();

    // Deserialize transaction data
    uint32_t vtx_size = read_uint32();
    if (data_offset + vtx_size > data.size()) {
        std::cerr << "[ERROR] ReadBlock: vtx size exceeds data" << std::endl;
        return false;
    }

    block.vtx.resize(vtx_size);
    if (vtx_size > 0) {
        std::memcpy(block.vtx.data(), data_ptr + data_offset, vtx_size);
        data_offset += vtx_size;
    }

    return true;
}

bool CBlockchainDB::WriteBlockIndex(const uint256& hash, const CBlockIndex& index) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "i" + hash.GetHex();

    // Serialize index - binary format with versioning and integrity checks
    // Format: [VERSION][DATA_LENGTH][DATA][CHECKSUM]
    std::string value;
    value.reserve(256);  // Reserve space for efficiency

    // Version 1 format marker (for future compatibility)
    const uint32_t SERIALIZATION_VERSION = 1;
    value.append(reinterpret_cast<const char*>(&SERIALIZATION_VERSION), sizeof(SERIALIZATION_VERSION));

    // Build data section
    std::string data;
    data.reserve(128);

    auto append_int32 = [&data](int32_t v) {
        data.append(reinterpret_cast<const char*>(&v), sizeof(v));
    };
    auto append_uint32 = [&data](uint32_t v) {
        data.append(reinterpret_cast<const char*>(&v), sizeof(v));
    };

    // Serialize critical fields
    append_int32(index.nHeight);
    append_uint32(index.nStatus);
    append_uint32(index.nTime);
    append_uint32(index.nBits);
    append_uint32(index.nNonce);
    append_int32(index.nVersion);
    append_uint32(index.nTx);

    // Serialize block hash (64 bytes hex string)
    std::string hashHex = index.phashBlock.GetHex();
    data.append(hashHex);

    // Write data length
    uint32_t data_length = static_cast<uint32_t>(data.size());
    value.append(reinterpret_cast<const char*>(&data_length), sizeof(data_length));

    // Write data
    value.append(data);

    // Calculate and append simple checksum (sum of all bytes mod 2^32)
    uint32_t checksum = 0;
    for (unsigned char c : data) {
        checksum += c;
    }
    value.append(reinterpret_cast<const char*>(&checksum), sizeof(checksum));

    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

bool CBlockchainDB::ReadBlockIndex(const uint256& hash, CBlockIndex& index) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "i" + hash.GetHex();
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return false;
    }

    // Check minimum size for versioned format
    const size_t MIN_SIZE = sizeof(uint32_t) * 3;  // version + length + checksum
    if (value.size() < MIN_SIZE) {
        std::cerr << "[ERROR] ReadBlockIndex: Data too small (" << value.size() << " bytes)" << std::endl;
        return false;
    }

    const char* ptr = value.data();
    size_t offset = 0;

    // Read and validate version
    uint32_t version;
    std::memcpy(&version, ptr + offset, sizeof(version));
    offset += sizeof(version);

    if (version != 1) {
        std::cerr << "[ERROR] ReadBlockIndex: Unsupported version " << version << std::endl;
        return false;
    }

    // Read data length
    uint32_t data_length;
    std::memcpy(&data_length, ptr + offset, sizeof(data_length));
    offset += sizeof(data_length);

    // Validate data length
    const size_t expected_total_size = sizeof(version) + sizeof(data_length) + data_length + sizeof(uint32_t);
    if (value.size() != expected_total_size) {
        std::cerr << "[ERROR] ReadBlockIndex: Size mismatch. Expected " << expected_total_size
                  << ", got " << value.size() << std::endl;
        return false;
    }

    // Extract data section
    if (offset + data_length > value.size()) {
        std::cerr << "[ERROR] ReadBlockIndex: Data length exceeds buffer" << std::endl;
        return false;
    }

    std::string data = value.substr(offset, data_length);
    offset += data_length;

    // Read and verify checksum
    uint32_t stored_checksum;
    std::memcpy(&stored_checksum, ptr + offset, sizeof(stored_checksum));

    uint32_t calculated_checksum = 0;
    for (unsigned char c : data) {
        calculated_checksum += c;
    }

    if (stored_checksum != calculated_checksum) {
        std::cerr << "[ERROR] ReadBlockIndex: Checksum mismatch. Stored: " << stored_checksum
                  << ", Calculated: " << calculated_checksum << std::endl;
        return false;
    }

    // Deserialize data with bounds checking
    const char* data_ptr = data.data();
    size_t data_offset = 0;

    auto read_int32 = [&data_ptr, &data_offset, &data]() -> int32_t {
        if (data_offset + sizeof(int32_t) > data.size()) return 0;
        int32_t v;
        std::memcpy(&v, data_ptr + data_offset, sizeof(v));
        data_offset += sizeof(v);
        return v;
    };
    auto read_uint32 = [&data_ptr, &data_offset, &data]() -> uint32_t {
        if (data_offset + sizeof(uint32_t) > data.size()) return 0;
        uint32_t v;
        std::memcpy(&v, data_ptr + data_offset, sizeof(v));
        data_offset += sizeof(v);
        return v;
    };

    // Deserialize critical fields
    index.nHeight = read_int32();
    index.nStatus = read_uint32();
    index.nTime = read_uint32();
    index.nBits = read_uint32();
    index.nNonce = read_uint32();
    index.nVersion = read_int32();
    index.nTx = read_uint32();

    // Deserialize block hash (remaining bytes are hex string)
    if (data_offset < data.size()) {
        std::string hashHex = data.substr(data_offset);
        if (hashHex.length() != 64) {
            std::cerr << "[ERROR] ReadBlockIndex: Invalid hash length " << hashHex.length() << std::endl;
            return false;
        }
        index.phashBlock.SetHex(hashHex);
    } else {
        std::cerr << "[ERROR] ReadBlockIndex: No hash data" << std::endl;
        return false;
    }

    return true;
}

bool CBlockchainDB::WriteBestBlock(const uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "bestblock";
    std::string value = hash.GetHex();

    leveldb::Status status = db->Put(leveldb::WriteOptions(), key, value);
    if (!status.ok()) {
        std::cerr << "[Error] WriteBestBlock: LevelDB Put failed: " << status.ToString() << std::endl;
    }
    return status.ok();
}

bool CBlockchainDB::ReadBestBlock(uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "bestblock";
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return false;
    }

    if (value.empty()) {
        return false;
    }

    hash.SetHex(value);
    return true;
}

bool CBlockchainDB::BlockExists(const uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();
    std::string value;

    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &value);
    return status.ok();
}

bool CBlockchainDB::EraseBlock(const uint256& hash) {
    if (!IsOpen()) return false;

    std::lock_guard<std::mutex> lock(cs_db);

    std::string key = "b" + hash.GetHex();

    leveldb::Status status = db->Delete(leveldb::WriteOptions(), key);
    return status.ok();
}
