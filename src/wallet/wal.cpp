// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wal.h>
#include <crypto/sha3.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <random>
#include <iomanip>
#include <sstream>
#include <map>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/file.h>
    #include <sys/stat.h>
#endif

// WAL File Magic Number and Version
static const char WAL_MAGIC[8] = {'D', 'I', 'L', 'W', 'W', 'A', 'L', '1'};
static const uint32_t WAL_VERSION = 1;

// Maximum sizes (security limits)
static const uint16_t MAX_OPERATION_ID_LENGTH = 256;
static const uint16_t MAX_STEP_NAME_LENGTH = 256;
static const uint32_t MAX_STEP_DATA_LENGTH = 1024 * 1024; // 1MB

//=============================================================================
// CRC32 Implementation (for entry integrity checking)
//=============================================================================

/**
 * CRC32 lookup table (generated once)
 * Standard CRC32 polynomial: 0xEDB88320
 */
static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

static void init_crc32_table() {
    if (crc32_table_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = true;
}

static uint32_t calculate_crc32(const uint8_t* data, size_t length) {
    init_crc32_table();

    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[index];
    }
    return crc ^ 0xFFFFFFFF;
}

//=============================================================================
// Helper Functions
//=============================================================================

const char* WALOperationToString(WALOperation op) {
    switch (op) {
        case WALOperation::WALLET_INITIALIZATION: return "WALLET_INITIALIZATION";
        case WALOperation::WALLET_ENCRYPTION: return "WALLET_ENCRYPTION";
        case WALOperation::HD_WALLET_CREATION: return "HD_WALLET_CREATION";
        case WALOperation::HD_WALLET_RESTORE: return "HD_WALLET_RESTORE";
        default: return "UNKNOWN";
    }
}

const char* WALEntryTypeToString(WALEntryType type) {
    switch (type) {
        case WALEntryType::BEGIN_OPERATION: return "BEGIN";
        case WALEntryType::CHECKPOINT: return "CHECKPOINT";
        case WALEntryType::COMMIT: return "COMMIT";
        case WALEntryType::ROLLBACK: return "ROLLBACK";
        default: return "UNKNOWN";
    }
}

// Write uint16_t in little-endian format
static void write_uint16_le(std::vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

// Write uint32_t in little-endian format
static void write_uint32_le(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

// Write uint64_t in little-endian format
static void write_uint64_le(std::vector<uint8_t>& buffer, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        buffer.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

// Read uint16_t in little-endian format
static uint16_t read_uint16_le(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

// Read uint32_t in little-endian format
static uint32_t read_uint32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

// Read uint64_t in little-endian format
static uint64_t read_uint64_le(const uint8_t* data) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= (static_cast<uint64_t>(data[i]) << (i * 8));
    }
    return result;
}

//=============================================================================
// WALEntry Implementation
//=============================================================================

WALEntry::WALEntry()
    : type(WALEntryType::BEGIN_OPERATION)
    , timestamp(0)
    , crc32(0)
{
}

std::vector<uint8_t> WALEntry::Serialize() const {
    std::vector<uint8_t> buffer;

    // Validate lengths
    if (operation_id.length() > MAX_OPERATION_ID_LENGTH) {
        std::cerr << "[WAL ERROR] Operation ID too long: " << operation_id.length() << " bytes" << std::endl;
        return {};
    }
    if (step_name.length() > MAX_STEP_NAME_LENGTH) {
        std::cerr << "[WAL ERROR] Step name too long: " << step_name.length() << " bytes" << std::endl;
        return {};
    }
    if (data.size() > MAX_STEP_DATA_LENGTH) {
        std::cerr << "[WAL ERROR] Step data too large: " << data.size() << " bytes" << std::endl;
        return {};
    }

    // Type (1 byte)
    buffer.push_back(static_cast<uint8_t>(type));

    // Operation ID length (2 bytes) + Operation ID
    write_uint16_le(buffer, static_cast<uint16_t>(operation_id.length()));
    buffer.insert(buffer.end(), operation_id.begin(), operation_id.end());

    // Step name length (2 bytes) + Step name
    write_uint16_le(buffer, static_cast<uint16_t>(step_name.length()));
    buffer.insert(buffer.end(), step_name.begin(), step_name.end());

    // Data length (4 bytes) + Data
    write_uint32_le(buffer, static_cast<uint32_t>(data.size()));
    buffer.insert(buffer.end(), data.begin(), data.end());

    // Timestamp (8 bytes)
    write_uint64_le(buffer, timestamp);

    // CRC32 (4 bytes) - calculated over all preceding bytes
    uint32_t calculated_crc = calculate_crc32(buffer.data(), buffer.size());
    write_uint32_le(buffer, calculated_crc);

    return buffer;
}

bool WALEntry::Deserialize(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 1 + 2 + 2 + 4 + 8 + 4) {
        std::cerr << "[WAL ERROR] Entry too small: " << bytes.size() << " bytes" << std::endl;
        return false;
    }

    size_t offset = 0;

    // Type (1 byte)
    type = static_cast<WALEntryType>(bytes[offset++]);

    // Operation ID length (2 bytes)
    uint16_t opid_len = read_uint16_le(&bytes[offset]);
    offset += 2;

    if (opid_len > MAX_OPERATION_ID_LENGTH) {
        std::cerr << "[WAL ERROR] Invalid operation ID length: " << opid_len << std::endl;
        return false;
    }

    if (offset + opid_len > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated operation ID" << std::endl;
        return false;
    }

    // Operation ID
    operation_id.assign(reinterpret_cast<const char*>(&bytes[offset]), opid_len);
    offset += opid_len;

    // Step name length (2 bytes)
    if (offset + 2 > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated step name length" << std::endl;
        return false;
    }
    uint16_t step_len = read_uint16_le(&bytes[offset]);
    offset += 2;

    if (step_len > MAX_STEP_NAME_LENGTH) {
        std::cerr << "[WAL ERROR] Invalid step name length: " << step_len << std::endl;
        return false;
    }

    if (offset + step_len > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated step name" << std::endl;
        return false;
    }

    // Step name
    step_name.assign(reinterpret_cast<const char*>(&bytes[offset]), step_len);
    offset += step_len;

    // Data length (4 bytes)
    if (offset + 4 > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated data length" << std::endl;
        return false;
    }
    uint32_t data_len = read_uint32_le(&bytes[offset]);
    offset += 4;

    if (data_len > MAX_STEP_DATA_LENGTH) {
        std::cerr << "[WAL ERROR] Invalid data length: " << data_len << std::endl;
        return false;
    }

    if (offset + data_len > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated data" << std::endl;
        return false;
    }

    // Data
    data.assign(bytes.begin() + offset, bytes.begin() + offset + data_len);
    offset += data_len;

    // Timestamp (8 bytes)
    if (offset + 8 > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated timestamp" << std::endl;
        return false;
    }
    timestamp = read_uint64_le(&bytes[offset]);
    offset += 8;

    // CRC32 (4 bytes)
    if (offset + 4 > bytes.size()) {
        std::cerr << "[WAL ERROR] Truncated CRC32" << std::endl;
        return false;
    }
    crc32 = read_uint32_le(&bytes[offset]);
    offset += 4;

    // Verify CRC32
    uint32_t calculated_crc = calculate_crc32(bytes.data(), offset - 4);
    if (calculated_crc != crc32) {
        std::cerr << "[WAL ERROR] CRC32 mismatch: expected " << std::hex << crc32
                  << ", got " << calculated_crc << std::dec << std::endl;
        return false;
    }

    return true;
}

uint32_t WALEntry::CalculateCRC32() const {
    // Serialize entry without CRC32 field
    std::vector<uint8_t> buffer;
    buffer.push_back(static_cast<uint8_t>(type));
    write_uint16_le(buffer, static_cast<uint16_t>(operation_id.length()));
    buffer.insert(buffer.end(), operation_id.begin(), operation_id.end());
    write_uint16_le(buffer, static_cast<uint16_t>(step_name.length()));
    buffer.insert(buffer.end(), step_name.begin(), step_name.end());
    write_uint32_le(buffer, static_cast<uint32_t>(data.size()));
    buffer.insert(buffer.end(), data.begin(), data.end());
    write_uint64_le(buffer, timestamp);

    return calculate_crc32(buffer.data(), buffer.size());
}

bool WALEntry::VerifyCRC32() const {
    return (CalculateCRC32() == crc32);
}

//=============================================================================
// CWalletWAL Implementation
//=============================================================================

CWalletWAL::CWalletWAL()
    : m_wal_initialized(false)
#ifdef _WIN32
    , m_file_handle(INVALID_HANDLE_VALUE)
#else
    , m_file_descriptor(-1)
#endif
{
}

CWalletWAL::~CWalletWAL() {
    CloseWAL();
}

bool CWalletWAL::Initialize(const std::string& wallet_path) {
    if (wallet_path.empty()) {
        std::cerr << "[WAL ERROR] Empty wallet path" << std::endl;
        return false;
    }

    m_wallet_file = wallet_path;
    m_wal_file = wallet_path + ".wal";
    m_wal_initialized = true;

    std::cout << "[WAL] Initialized for wallet: " << m_wallet_file << std::endl;
    std::cout << "[WAL] WAL file: " << m_wal_file << std::endl;

    return true;
}

std::string CWalletWAL::GenerateOperationID() const {
    // Generate UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // Where x is random hex, y is 8/9/a/b

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);

    uint32_t parts[4];
    for (int i = 0; i < 4; i++) {
        parts[i] = dis(gen);
    }

    // Set version (4) and variant (RFC 4122)
    parts[1] = (parts[1] & 0xFFFF0FFF) | 0x00004000; // Version 4
    parts[2] = (parts[2] & 0x3FFFFFFF) | 0x80000000; // Variant 10

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << parts[0] << "-";
    oss << std::setw(4) << ((parts[1] >> 16) & 0xFFFF) << "-";
    oss << std::setw(4) << (parts[1] & 0xFFFF) << "-";
    oss << std::setw(4) << ((parts[2] >> 16) & 0xFFFF) << "-";
    oss << std::setw(4) << (parts[2] & 0xFFFF);
    oss << std::setw(8) << parts[3];

    return oss.str();
}

bool CWalletWAL::WriteEntry(const WALEntry& entry) {
    if (!m_wal_initialized) {
        std::cerr << "[WAL ERROR] WAL not initialized" << std::endl;
        return false;
    }

    // Serialize entry
    std::vector<uint8_t> serialized = entry.Serialize();
    if (serialized.empty()) {
        std::cerr << "[WAL ERROR] Failed to serialize entry" << std::endl;
        return false;
    }

    // Open WAL file for append
    std::ofstream wal_stream(m_wal_file, std::ios::binary | std::ios::app);
    if (!wal_stream.is_open()) {
        std::cerr << "[WAL ERROR] Failed to open WAL file for append: " << m_wal_file << std::endl;
        return false;
    }

    // Write serialized entry
    wal_stream.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());
    if (!wal_stream.good()) {
        std::cerr << "[WAL ERROR] Failed to write entry to WAL" << std::endl;
        wal_stream.close();
        return false;
    }

    // Flush and sync to disk (durability)
    wal_stream.flush();
    wal_stream.close();

#ifndef _WIN32
    // Linux: Use fsync to ensure data written to physical disk
    int fd = open(m_wal_file.c_str(), O_RDONLY);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
#endif

    std::cout << "[WAL] Wrote " << WALEntryTypeToString(entry.type)
              << " entry (op=" << entry.operation_id.substr(0, 8) << "...)" << std::endl;

    return true;
}

bool CWalletWAL::ReadEntries(std::vector<WALEntry>& entries_out) const {
    entries_out.clear();

    if (!m_wal_initialized) {
        std::cerr << "[WAL ERROR] WAL not initialized" << std::endl;
        return false;
    }

    // Check if WAL file exists
    std::ifstream wal_stream(m_wal_file, std::ios::binary | std::ios::ate);
    if (!wal_stream.is_open()) {
        // No WAL file = no incomplete operations (normal)
        return true;
    }

    // Get file size
    std::streamsize file_size = wal_stream.tellg();
    wal_stream.seekg(0, std::ios::beg);

    if (file_size < 16) {
        std::cerr << "[WAL ERROR] WAL file too small (missing header)" << std::endl;
        wal_stream.close();
        return false;
    }

    // Read header
    char magic[8];
    wal_stream.read(magic, 8);
    if (std::memcmp(magic, WAL_MAGIC, 8) != 0) {
        std::cerr << "[WAL ERROR] Invalid magic number" << std::endl;
        wal_stream.close();
        return false;
    }

    uint32_t version;
    wal_stream.read(reinterpret_cast<char*>(&version), 4);
    version = read_uint32_le(reinterpret_cast<const uint8_t*>(&version));
    if (version != WAL_VERSION) {
        std::cerr << "[WAL ERROR] Unsupported WAL version: " << version << std::endl;
        wal_stream.close();
        return false;
    }

    uint32_t entry_count;
    wal_stream.read(reinterpret_cast<char*>(&entry_count), 4);
    entry_count = read_uint32_le(reinterpret_cast<const uint8_t*>(&entry_count));

    std::cout << "[WAL] Reading WAL file: " << entry_count << " entries" << std::endl;

    // Read entries
    for (uint32_t i = 0; i < entry_count && wal_stream.good(); i++) {
        // Read entry size (we need to read variable-length entry)
        // Strategy: Read minimum entry size, then read rest based on lengths

        std::vector<uint8_t> entry_buffer(file_size - wal_stream.tellg());
        wal_stream.read(reinterpret_cast<char*>(entry_buffer.data()), entry_buffer.size());

        // Try to deserialize
        WALEntry entry;
        if (!entry.Deserialize(entry_buffer)) {
            std::cerr << "[WAL ERROR] Failed to deserialize entry " << i << std::endl;
            wal_stream.close();
            return false;
        }

        entries_out.push_back(entry);

        // Calculate actual entry size and seek to next entry
        size_t entry_size = entry.Serialize().size();
        wal_stream.seekg(16 + entry_size * (i + 1));
    }

    wal_stream.close();
    std::cout << "[WAL] Successfully read " << entries_out.size() << " entries" << std::endl;

    return true;
}

bool CWalletWAL::OpenWAL() {
    // This is a simplified version - in production, would implement file locking
    return true;
}

void CWalletWAL::CloseWAL() {
#ifdef _WIN32
    if (m_file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_file_handle);
        m_file_handle = INVALID_HANDLE_VALUE;
    }
#else
    if (m_file_descriptor >= 0) {
        close(m_file_descriptor);
        m_file_descriptor = -1;
    }
#endif
}

bool CWalletWAL::SecureDelete(const std::string& filepath) {
    // Get file size
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return true; // File doesn't exist = already deleted
    }
    std::streamsize file_size = file.tellg();
    file.close();

    // Overwrite with zeros
    std::ofstream overwrite(filepath, std::ios::binary);
    if (!overwrite.is_open()) {
        std::cerr << "[WAL ERROR] Failed to open file for secure deletion: " << filepath << std::endl;
        return false;
    }

    std::vector<uint8_t> zeros(4096, 0);
    for (std::streamsize written = 0; written < file_size; written += zeros.size()) {
        size_t to_write = std::min(static_cast<size_t>(file_size - written), zeros.size());
        overwrite.write(reinterpret_cast<const char*>(zeros.data()), to_write);
    }
    overwrite.close();

    // Delete file
#ifdef _WIN32
    if (!DeleteFileA(filepath.c_str())) {
        std::cerr << "[WAL ERROR] Failed to delete file: " << filepath << std::endl;
        return false;
    }
#else
    if (unlink(filepath.c_str()) != 0) {
        std::cerr << "[WAL ERROR] Failed to delete file: " << filepath << std::endl;
        return false;
    }
#endif

    std::cout << "[WAL] Securely deleted file: " << filepath << std::endl;
    return true;
}

bool CWalletWAL::WriteHeader(uint32_t entry_count) {
    std::ofstream wal_stream(m_wal_file, std::ios::binary);
    if (!wal_stream.is_open()) {
        std::cerr << "[WAL ERROR] Failed to create WAL file: " << m_wal_file << std::endl;
        return false;
    }

    // Write magic
    wal_stream.write(WAL_MAGIC, 8);

    // Write version (little-endian)
    uint32_t version_le = WAL_VERSION;
    wal_stream.write(reinterpret_cast<const char*>(&version_le), 4);

    // Write entry count (little-endian)
    uint32_t count_le = entry_count;
    wal_stream.write(reinterpret_cast<const char*>(&count_le), 4);

    wal_stream.close();

    std::cout << "[WAL] Created WAL file with header" << std::endl;

    return true;
}

bool CWalletWAL::BeginOperation(WALOperation op, std::string& operation_id_out) {
    if (!m_wal_initialized) {
        std::cerr << "[WAL ERROR] WAL not initialized" << std::endl;
        return false;
    }

    // Generate operation ID
    std::string op_id = GenerateOperationID();

    // Create WAL file if it doesn't exist
    if (!WALFileExists()) {
        if (!WriteHeader(0)) {
            return false;
        }
    }

    // Create BEGIN entry
    WALEntry entry;
    entry.type = WALEntryType::BEGIN_OPERATION;
    entry.operation_id = op_id;
    entry.step_name = std::string(1, static_cast<char>(op)); // Encode operation type as first byte
    entry.timestamp = static_cast<uint64_t>(std::time(nullptr));
    entry.crc32 = entry.CalculateCRC32();

    if (!WriteEntry(entry)) {
        return false;
    }

    m_current_operation_id = op_id;
    operation_id_out = op_id;

    std::cout << "[WAL] Began operation " << WALOperationToString(op)
              << " (id=" << op_id.substr(0, 8) << "...)" << std::endl;

    return true;
}

bool CWalletWAL::Checkpoint(const std::string& operation_id,
                             const std::string& step_name,
                             const std::vector<uint8_t>& step_data) {
    if (!m_wal_initialized) {
        std::cerr << "[WAL ERROR] WAL not initialized" << std::endl;
        return false;
    }

    // Create CHECKPOINT entry
    WALEntry entry;
    entry.type = WALEntryType::CHECKPOINT;
    entry.operation_id = operation_id;
    entry.step_name = step_name;
    entry.data = step_data;
    entry.timestamp = static_cast<uint64_t>(std::time(nullptr));
    entry.crc32 = entry.CalculateCRC32();

    if (!WriteEntry(entry)) {
        return false;
    }

    std::cout << "[WAL] Checkpoint: " << step_name << " (op=" << operation_id.substr(0, 8) << "...)" << std::endl;

    return true;
}

bool CWalletWAL::Commit(const std::string& operation_id) {
    if (!m_wal_initialized) {
        std::cerr << "[WAL ERROR] WAL not initialized" << std::endl;
        return false;
    }

    // Create COMMIT entry
    WALEntry entry;
    entry.type = WALEntryType::COMMIT;
    entry.operation_id = operation_id;
    entry.timestamp = static_cast<uint64_t>(std::time(nullptr));
    entry.crc32 = entry.CalculateCRC32();

    if (!WriteEntry(entry)) {
        return false;
    }

    std::cout << "[WAL] Committed operation (op=" << operation_id.substr(0, 8) << "...)" << std::endl;

    // Delete WAL file after successful commit
    if (!DeleteWAL()) {
        std::cerr << "[WAL WARNING] Failed to delete WAL file after commit" << std::endl;
        // Not fatal - WAL recovery will handle it
    }

    m_current_operation_id.clear();

    return true;
}

bool CWalletWAL::Rollback(const std::string& operation_id) {
    if (!m_wal_initialized) {
        std::cerr << "[WAL ERROR] WAL not initialized" << std::endl;
        return false;
    }

    // Create ROLLBACK entry
    WALEntry entry;
    entry.type = WALEntryType::ROLLBACK;
    entry.operation_id = operation_id;
    entry.timestamp = static_cast<uint64_t>(std::time(nullptr));
    entry.crc32 = entry.CalculateCRC32();

    if (!WriteEntry(entry)) {
        return false;
    }

    std::cout << "[WAL] Rolled back operation (op=" << operation_id.substr(0, 8) << "...)" << std::endl;

    // Delete WAL file after rollback
    if (!DeleteWAL()) {
        std::cerr << "[WAL WARNING] Failed to delete WAL file after rollback" << std::endl;
    }

    m_current_operation_id.clear();

    return true;
}

bool CWalletWAL::HasIncompleteOperations(std::vector<std::string>& operations_out) const {
    operations_out.clear();

    // Read all entries
    std::vector<WALEntry> entries;
    if (!ReadEntries(entries)) {
        return false;
    }

    if (entries.empty()) {
        return true; // No entries = no incomplete operations
    }

    // Track operation states
    std::map<std::string, bool> operation_complete;

    for (const auto& entry : entries) {
        if (entry.type == WALEntryType::BEGIN_OPERATION) {
            operation_complete[entry.operation_id] = false;
        } else if (entry.type == WALEntryType::COMMIT || entry.type == WALEntryType::ROLLBACK) {
            operation_complete[entry.operation_id] = true;
        }
    }

    // Find incomplete operations
    for (const auto& pair : operation_complete) {
        if (!pair.second) {
            operations_out.push_back(pair.first);
        }
    }

    if (!operations_out.empty()) {
        std::cout << "[WAL] Found " << operations_out.size() << " incomplete operations" << std::endl;
    }

    return true;
}

bool CWalletWAL::GetOperationDetails(const std::string& operation_id,
                                     WALOperation& op_type_out,
                                     std::vector<WALEntry>& steps_out) const {
    steps_out.clear();

    // Read all entries
    std::vector<WALEntry> entries;
    if (!ReadEntries(entries)) {
        return false;
    }

    // Find entries for this operation
    bool found = false;
    for (const auto& entry : entries) {
        if (entry.operation_id == operation_id) {
            if (entry.type == WALEntryType::BEGIN_OPERATION) {
                // Decode operation type from step_name (first byte)
                if (!entry.step_name.empty()) {
                    op_type_out = static_cast<WALOperation>(static_cast<uint8_t>(entry.step_name[0]));
                }
                found = true;
            }
            steps_out.push_back(entry);
        }
    }

    return found;
}

bool CWalletWAL::WALFileExists() const {
    std::ifstream file(m_wal_file);
    return file.good();
}

bool CWalletWAL::DeleteWAL() {
    if (!WALFileExists()) {
        return true; // Already deleted
    }

    return SecureDelete(m_wal_file);
}
