// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// P1-4 FIX: Write-Ahead Logging for Atomic Chain Reorganizations

#include <consensus/reorg_wal.h>
#include <crypto/sha3.h>
#include <iostream>
#include <cstring>
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #include <io.h>
    #define fsync(fd) _commit(fd)
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <unistd.h>
#endif

// Static member initialization
constexpr char CReorgWAL::MAGIC[16];

CReorgWAL::CReorgWAL(const std::string& dataDir)
    : m_active(false)
    , m_phase(ReorgPhase::INITIALIZED)
    , m_disconnectedCount(0)
    , m_connectedCount(0)
{
    // MAINNET FIX: Create WAL directory with proper permission handling
    std::string walDir = dataDir + "/wal";

#ifdef _WIN32
    // Windows: Create directory and check return value (CWE-252 fix)
    // Note: Windows mkdir doesn't support mode parameter, but we still check for errors
    if (mkdir(walDir.c_str(), 0) != 0 && errno != EEXIST) {
        std::cerr << "[WAL] WARNING: Failed to create WAL directory: "
                  << walDir << " (" << strerror(errno) << ")" << std::endl;
    }
#else
    // Unix: Try mkdir directly to avoid TOCTOU race (CWE-367 fix)
    // mkdir() is atomic - either creates or fails with EEXIST
    int mkdirResult = mkdir(walDir.c_str(), 0700);
    if (mkdirResult != 0 && errno != EEXIST) {
        std::cerr << "[WAL] WARNING: Failed to create WAL directory: "
                  << walDir << " (" << strerror(errno) << ")" << std::endl;
    } else {
        // Directory created or already exists - check permissions (informational only)
        struct stat dirStat;
        if (stat(walDir.c_str(), &dirStat) == 0) {
            if (!S_ISDIR(dirStat.st_mode)) {
                std::cerr << "[WAL] ERROR: " << walDir << " exists but is not a directory" << std::endl;
            } else if ((dirStat.st_mode & 077) != 0) {
                // Warn if group/others have any permissions
                std::cerr << "[WAL] WARNING: WAL directory has insecure permissions (mode "
                          << std::oct << (dirStat.st_mode & 0777) << std::dec << ")" << std::endl;
                std::cerr << "[WAL] Consider: chmod 700 " << walDir << std::endl;
            }
        }
    }
#endif

    m_walPath = walDir + "/reorg_pending.dat";

    // Check if WAL exists (incomplete reorg from crash)
    struct stat buffer;
    if (stat(m_walPath.c_str(), &buffer) == 0) {
        // WAL exists - read it
        if (ReadWAL()) {
            // Successfully read WAL - incomplete reorg detected
            if (m_phase != ReorgPhase::COMPLETED) {
                std::cerr << "[WAL] *** INCOMPLETE REORG DETECTED ***" << std::endl;
                std::cerr << "[WAL] " << GetIncompleteReorgInfo() << std::endl;
            } else {
                // Reorg was completed but WAL not deleted (crash after reorg, before delete)
                // Safe to delete WAL and continue
                std::cout << "[WAL] Found completed reorg WAL - cleaning up" << std::endl;
                CompleteReorg();
            }
        } else {
            std::cerr << "[WAL] WARNING: Found corrupt WAL file - deleting" << std::endl;
            std::remove(m_walPath.c_str());
        }
    }
}

CReorgWAL::~CReorgWAL() {
    // If active and not completed, this is bad - but we can't do much in destructor
    if (m_active && m_phase != ReorgPhase::COMPLETED) {
        std::cerr << "[WAL] WARNING: Destructor called with active incomplete reorg!" << std::endl;
    }
}

bool CReorgWAL::HasIncompleteReorg() const {
    struct stat buffer;
    if (stat(m_walPath.c_str(), &buffer) != 0) {
        return false;  // No WAL file
    }

    // WAL exists - check if it's incomplete
    return m_phase != ReorgPhase::COMPLETED && m_phase != ReorgPhase::INITIALIZED;
}

std::string CReorgWAL::GetIncompleteReorgInfo() const {
    std::string info = "Incomplete reorg detected:\n";
    info += "  Fork point: " + m_forkPointHash.GetHex().substr(0, 16) + "...\n";
    info += "  Current tip: " + m_currentTipHash.GetHex().substr(0, 16) + "...\n";
    info += "  Target tip: " + m_targetTipHash.GetHex().substr(0, 16) + "...\n";
    info += "  Phase: ";

    switch (m_phase) {
        case ReorgPhase::INITIALIZED:
            info += "INITIALIZED (reorg not started)";
            break;
        case ReorgPhase::DISCONNECTING:
            info += "DISCONNECTING (" + std::to_string(m_disconnectedCount) + "/" +
                    std::to_string(m_disconnectHashes.size()) + " blocks)";
            break;
        case ReorgPhase::CONNECTING:
            info += "CONNECTING (" + std::to_string(m_connectedCount) + "/" +
                    std::to_string(m_connectHashes.size()) + " blocks)";
            break;
        case ReorgPhase::COMPLETED:
            info += "COMPLETED";
            break;
    }

    info += "\n\nRECOVERY: Restart with -reindex to rebuild the database.";
    return info;
}

void CReorgWAL::ComputeChecksum(uint8_t* checksum) const {
    // Serialize WAL state for checksum
    std::vector<uint8_t> data;

    // Add phase
    data.push_back(static_cast<uint8_t>(m_phase));

    // Add hashes
    data.insert(data.end(), m_forkPointHash.begin(), m_forkPointHash.end());
    data.insert(data.end(), m_currentTipHash.begin(), m_currentTipHash.end());
    data.insert(data.end(), m_targetTipHash.begin(), m_targetTipHash.end());

    // Add disconnect hashes
    uint32_t disconnectCount = static_cast<uint32_t>(m_disconnectHashes.size());
    data.push_back(disconnectCount & 0xFF);
    data.push_back((disconnectCount >> 8) & 0xFF);
    data.push_back((disconnectCount >> 16) & 0xFF);
    data.push_back((disconnectCount >> 24) & 0xFF);

    for (const auto& hash : m_disconnectHashes) {
        data.insert(data.end(), hash.begin(), hash.end());
    }

    // Add connect hashes
    uint32_t connectCount = static_cast<uint32_t>(m_connectHashes.size());
    data.push_back(connectCount & 0xFF);
    data.push_back((connectCount >> 8) & 0xFF);
    data.push_back((connectCount >> 16) & 0xFF);
    data.push_back((connectCount >> 24) & 0xFF);

    for (const auto& hash : m_connectHashes) {
        data.insert(data.end(), hash.begin(), hash.end());
    }

    // Add progress counters
    data.push_back(m_disconnectedCount & 0xFF);
    data.push_back((m_disconnectedCount >> 8) & 0xFF);
    data.push_back((m_disconnectedCount >> 16) & 0xFF);
    data.push_back((m_disconnectedCount >> 24) & 0xFF);

    data.push_back(m_connectedCount & 0xFF);
    data.push_back((m_connectedCount >> 8) & 0xFF);
    data.push_back((m_connectedCount >> 16) & 0xFF);
    data.push_back((m_connectedCount >> 24) & 0xFF);

    // Compute SHA3-256
    SHA3_256(data.data(), data.size(), checksum);
}

bool CReorgWAL::WriteWAL() {
    std::ofstream file(m_walPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "[WAL] ERROR: Cannot open WAL file for writing: " << m_walPath << std::endl;
        return false;
    }

    // Write magic
    file.write(MAGIC, 16);

    // Write version
    file.write(reinterpret_cast<const char*>(&VERSION), 4);

    // Write phase
    uint8_t phase = static_cast<uint8_t>(m_phase);
    file.write(reinterpret_cast<const char*>(&phase), 1);

    // Write hashes
    file.write(reinterpret_cast<const char*>(m_forkPointHash.begin()), 32);
    file.write(reinterpret_cast<const char*>(m_currentTipHash.begin()), 32);
    file.write(reinterpret_cast<const char*>(m_targetTipHash.begin()), 32);

    // Write disconnect hashes
    uint32_t disconnectCount = static_cast<uint32_t>(m_disconnectHashes.size());
    file.write(reinterpret_cast<const char*>(&disconnectCount), 4);
    for (const auto& hash : m_disconnectHashes) {
        file.write(reinterpret_cast<const char*>(hash.begin()), 32);
    }

    // Write connect hashes
    uint32_t connectCount = static_cast<uint32_t>(m_connectHashes.size());
    file.write(reinterpret_cast<const char*>(&connectCount), 4);
    for (const auto& hash : m_connectHashes) {
        file.write(reinterpret_cast<const char*>(hash.begin()), 32);
    }

    // Write progress counters
    file.write(reinterpret_cast<const char*>(&m_disconnectedCount), 4);
    file.write(reinterpret_cast<const char*>(&m_connectedCount), 4);

    // Write checksum
    uint8_t checksum[32];
    ComputeChecksum(checksum);
    file.write(reinterpret_cast<const char*>(checksum), 32);

    // Flush and sync
    file.flush();

    // Force sync to disk (critical for crash recovery)
#ifdef _WIN32
    file.close();
    // On Windows, use FlushFileBuffers via _commit in next file operation
    // The flush above + close should be sufficient on NTFS
#else
    // On Unix, use fsync
    int fd = fileno(reinterpret_cast<FILE*>(file.rdbuf()));
    if (fd >= 0) {
        fsync(fd);
    }
    file.close();
#endif

    if (file.bad()) {
        std::cerr << "[WAL] ERROR: Failed to write WAL file" << std::endl;
        return false;
    }

    return true;
}

bool CReorgWAL::ReadWAL() {
    std::ifstream file(m_walPath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // Read and verify magic
    char magic[16];
    file.read(magic, 16);
    if (std::memcmp(magic, MAGIC, 16) != 0) {
        std::cerr << "[WAL] ERROR: Invalid WAL magic" << std::endl;
        return false;
    }

    // Read and verify version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), 4);
    if (version != VERSION) {
        std::cerr << "[WAL] ERROR: Unsupported WAL version: " << version << std::endl;
        return false;
    }

    // Read phase
    uint8_t phase;
    file.read(reinterpret_cast<char*>(&phase), 1);
    m_phase = static_cast<ReorgPhase>(phase);

    // Read hashes
    file.read(reinterpret_cast<char*>(m_forkPointHash.begin()), 32);
    file.read(reinterpret_cast<char*>(m_currentTipHash.begin()), 32);
    file.read(reinterpret_cast<char*>(m_targetTipHash.begin()), 32);

    // Read disconnect hashes
    uint32_t disconnectCount;
    file.read(reinterpret_cast<char*>(&disconnectCount), 4);
    m_disconnectHashes.clear();
    m_disconnectHashes.resize(disconnectCount);
    for (uint32_t i = 0; i < disconnectCount; i++) {
        file.read(reinterpret_cast<char*>(m_disconnectHashes[i].begin()), 32);
    }

    // Read connect hashes
    uint32_t connectCount;
    file.read(reinterpret_cast<char*>(&connectCount), 4);
    m_connectHashes.clear();
    m_connectHashes.resize(connectCount);
    for (uint32_t i = 0; i < connectCount; i++) {
        file.read(reinterpret_cast<char*>(m_connectHashes[i].begin()), 32);
    }

    // Read progress counters
    file.read(reinterpret_cast<char*>(&m_disconnectedCount), 4);
    file.read(reinterpret_cast<char*>(&m_connectedCount), 4);

    // Read and verify checksum
    uint8_t storedChecksum[32];
    file.read(reinterpret_cast<char*>(storedChecksum), 32);

    uint8_t computedChecksum[32];
    ComputeChecksum(computedChecksum);

    if (std::memcmp(storedChecksum, computedChecksum, 32) != 0) {
        std::cerr << "[WAL] ERROR: WAL checksum mismatch - file corrupted" << std::endl;
        return false;
    }

    file.close();

    // Mark as active if not completed
    m_active = (m_phase != ReorgPhase::COMPLETED);

    return true;
}

bool CReorgWAL::BeginReorg(const uint256& forkPoint,
                           const uint256& currentTip,
                           const uint256& targetTip,
                           const std::vector<uint256>& disconnectBlocks,
                           const std::vector<uint256>& connectBlocks) {
    if (m_active) {
        std::cerr << "[WAL] ERROR: Cannot begin reorg - another reorg is already in progress" << std::endl;
        return false;
    }

    // Initialize state
    m_forkPointHash = forkPoint;
    m_currentTipHash = currentTip;
    m_targetTipHash = targetTip;
    m_disconnectHashes = disconnectBlocks;
    m_connectHashes = connectBlocks;
    m_phase = ReorgPhase::INITIALIZED;
    m_disconnectedCount = 0;
    m_connectedCount = 0;
    m_active = true;

    std::cout << "[WAL] Beginning reorg: disconnect " << disconnectBlocks.size()
              << " blocks, connect " << connectBlocks.size() << " blocks" << std::endl;

    return WriteWAL();
}

bool CReorgWAL::EnterDisconnectPhase() {
    if (!m_active) {
        std::cerr << "[WAL] ERROR: Cannot enter disconnect phase - no active reorg" << std::endl;
        return false;
    }

    m_phase = ReorgPhase::DISCONNECTING;
    m_disconnectedCount = 0;

    return WriteWAL();
}

bool CReorgWAL::UpdateDisconnectProgress(uint32_t count) {
    if (!m_active || m_phase != ReorgPhase::DISCONNECTING) {
        return false;
    }

    m_disconnectedCount = count;
    return WriteWAL();
}

bool CReorgWAL::EnterConnectPhase() {
    if (!m_active) {
        std::cerr << "[WAL] ERROR: Cannot enter connect phase - no active reorg" << std::endl;
        return false;
    }

    m_phase = ReorgPhase::CONNECTING;
    m_connectedCount = 0;

    return WriteWAL();
}

bool CReorgWAL::UpdateConnectProgress(uint32_t count) {
    if (!m_active || m_phase != ReorgPhase::CONNECTING) {
        return false;
    }

    m_connectedCount = count;
    return WriteWAL();
}

bool CReorgWAL::CompleteReorg() {
    // Delete WAL file
    if (std::remove(m_walPath.c_str()) != 0) {
        // File might not exist - that's OK
        struct stat buffer;
        if (stat(m_walPath.c_str(), &buffer) == 0) {
            std::cerr << "[WAL] WARNING: Failed to delete WAL file: " << m_walPath << std::endl;
        }
    }

    m_active = false;
    m_phase = ReorgPhase::COMPLETED;
    m_disconnectHashes.clear();
    m_connectHashes.clear();
    m_disconnectedCount = 0;
    m_connectedCount = 0;

    std::cout << "[WAL] Reorg completed successfully - WAL deleted" << std::endl;
    return true;
}

bool CReorgWAL::AbortReorg() {
    // Same as CompleteReorg - delete WAL
    // The in-memory rollback should have restored the original state
    std::cout << "[WAL] Reorg aborted - deleting WAL" << std::endl;
    return CompleteReorg();
}
