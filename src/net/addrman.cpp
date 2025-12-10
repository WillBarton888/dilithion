// Copyright (c) 2012-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/addrman.h>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>  // CID 1675210: For GetLastError and ERROR_FILE_NOT_FOUND
#endif

//-----------------------------------------------------------------------------
// CAddrInfo implementation
//-----------------------------------------------------------------------------

double CAddrInfo::GetChance(int64_t nNow) const {
    double fChance = 1.0;

    // Deprioritize very recent attempts
    int64_t nSinceLastTry = std::max((int64_t)0, nNow - nLastTry);

    if (nSinceLastTry < 60 * 10) {
        // Less than 10 minutes ago
        fChance *= 0.01;
    }

    // Deprioritize addresses with many failed attempts
    // 66% chance of selecting after each failure
    fChance *= std::pow(0.66, std::min(nAttempts, 8));

    return fChance;
}

bool CAddrInfo::IsTerrible(int64_t nNow) const {
    // Never succeeded and last attempt was recent
    if (nLastSuccess == 0 && nAttempts >= CAddrMan::ADDRMAN_RETRIES && nNow - nLastTry < 60) {
        return true;
    }

    // Hasn't been seen in 30 days
    if (nTime < nNow - CAddrMan::ADDRMAN_HORIZON_DAYS * 24 * 60 * 60) {
        return true;
    }

    // More than 10 failures in a row
    if (nAttempts >= CAddrMan::ADDRMAN_MAX_FAILURES) {
        return true;
    }

    // It's been a week since last success, and we've had failures
    if (nLastSuccess > 0 &&
        nNow - nLastSuccess > CAddrMan::ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60 &&
        nAttempts > 0) {
        return true;
    }

    return false;
}

//-----------------------------------------------------------------------------
// CAddrMan implementation
//-----------------------------------------------------------------------------

CAddrMan::CAddrMan()
    : nIdCount(0),
      nNew(0),
      nTried(0),
      nChecked(0) {
    // Initialize random key
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 4; i++) {
        uint64_t rnd = gen();
        std::memcpy(nKey.data + i * 8, &rnd, 8);
    }

    // Initialize RNG
    insecure_rand.seed(rd());

    // Initialize bucket tables to -1 (empty)
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            vvNew[bucket][i] = -1;
        }
    }

    for (int bucket = 0; bucket < ADDRMAN_TRIED_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            vvTried[bucket][i] = -1;
        }
    }
}

int64_t CAddrMan::GetAdjustedTime() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void CAddrMan::SetKey(const uint256& key) {
    std::lock_guard<std::mutex> lock(cs);
    nKey = key;
}

CAddrInfo* CAddrMan::Find(const CService& addr) {
    auto it = mapAddr.find(addr);
    if (it == mapAddr.end()) return nullptr;

    auto it2 = mapInfo.find(it->second);
    if (it2 == mapInfo.end()) return nullptr;

    return &it2->second;
}

const CAddrInfo* CAddrMan::Find(const CService& addr) const {
    auto it = mapAddr.find(addr);
    if (it == mapAddr.end()) return nullptr;

    auto it2 = mapInfo.find(it->second);
    if (it2 == mapInfo.end()) return nullptr;

    return &it2->second;
}

int CAddrMan::Create(const CNetworkAddr& addr, const CNetAddr& source, int* pnId) {
    int nId = nIdCount++;
    mapInfo[nId] = CAddrInfo(addr, source);
    mapAddr[addr] = nId;

    mapInfo[nId].nRandomPos = static_cast<int>(vRandom.size());
    vRandom.push_back(nId);

    if (pnId) *pnId = nId;
    return nId;
}

void CAddrMan::SwapRandom(int nRandomPos1, int nRandomPos2) {
    if (nRandomPos1 == nRandomPos2) return;

    int nId1 = vRandom[nRandomPos1];
    int nId2 = vRandom[nRandomPos2];

    auto it1 = mapInfo.find(nId1);
    auto it2 = mapInfo.find(nId2);

    if (it1 != mapInfo.end()) {
        it1->second.nRandomPos = nRandomPos2;
    }
    if (it2 != mapInfo.end()) {
        it2->second.nRandomPos = nRandomPos1;
    }

    vRandom[nRandomPos1] = nId2;
    vRandom[nRandomPos2] = nId1;
}

void CAddrMan::Delete(int nId) {
    auto it = mapInfo.find(nId);
    if (it == mapInfo.end()) return;

    CAddrInfo& info = it->second;

    // Swap with last element in random vector
    SwapRandom(info.nRandomPos, static_cast<int>(vRandom.size()) - 1);
    vRandom.pop_back();

    mapAddr.erase(info);
    mapInfo.erase(it);
}

void CAddrMan::ClearNew(int nUBucket, int nUBucketPos) {
    // If bucket position is occupied, remove reference
    if (vvNew[nUBucket][nUBucketPos] != -1) {
        int nIdDelete = vvNew[nUBucket][nUBucketPos];
        auto it = mapInfo.find(nIdDelete);

        if (it != mapInfo.end()) {
            CAddrInfo& infoDelete = it->second;
            infoDelete.nRefCount--;

            if (infoDelete.nRefCount <= 0) {
                Delete(nIdDelete);
                nNew--;
            }
        }

        vvNew[nUBucket][nUBucketPos] = -1;
    }
}

void CAddrMan::MakeTried(CAddrInfo& info, int nId) {
    // Remove from all new buckets
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        for (int pos = 0; pos < ADDRMAN_BUCKET_SIZE; pos++) {
            if (vvNew[bucket][pos] == nId) {
                vvNew[bucket][pos] = -1;
                info.nRefCount--;
            }
        }
    }

    nNew--;

    // Calculate tried bucket
    int nKBucket = GetTriedBucket(info);
    int nKBucketPos = GetBucketPosition(info, false, nKBucket);

    // If position is occupied, evict existing entry back to new
    if (vvTried[nKBucket][nKBucketPos] != -1) {
        int nIdEvict = vvTried[nKBucket][nKBucketPos];
        auto itEvict = mapInfo.find(nIdEvict);

        if (itEvict != mapInfo.end()) {
            CAddrInfo& infoEvict = itEvict->second;

            // Mark as not tried
            infoEvict.fInTried = false;
            nTried--;

            // Put back in new table
            int nNewBucket = GetNewBucket(infoEvict, infoEvict.source);
            int nNewBucketPos = GetBucketPosition(infoEvict, true, nNewBucket);

            ClearNew(nNewBucket, nNewBucketPos);
            vvNew[nNewBucket][nNewBucketPos] = nIdEvict;
            infoEvict.nRefCount++;
            nNew++;
        }
    }

    // Place in tried
    vvTried[nKBucket][nKBucketPos] = nId;
    nTried++;
    info.fInTried = true;
}

int CAddrMan::GetNewBucket(const CNetAddr& addr, const CNetAddr& source) const {
    // Get network groups
    std::vector<uint8_t> vchSourceGroup = source.GetGroup();
    std::vector<uint8_t> vchGroup = addr.GetGroup();

    // Hash: key + source_group + group
    // Concatenate all data into a buffer for one-shot hash
    std::vector<uint8_t> buffer;
    buffer.reserve(32 + vchSourceGroup.size() + vchGroup.size());
    buffer.insert(buffer.end(), nKey.data, nKey.data + 32);
    buffer.insert(buffer.end(), vchSourceGroup.begin(), vchSourceGroup.end());
    buffer.insert(buffer.end(), vchGroup.begin(), vchGroup.end());

    uint8_t hash[32];
    SHA3_256(buffer.data(), buffer.size(), hash);

    // Use first 8 bytes as bucket number
    uint64_t hash64;
    std::memcpy(&hash64, hash, 8);

    return static_cast<int>(hash64 % ADDRMAN_NEW_BUCKET_COUNT);
}

int CAddrMan::GetTriedBucket(const CNetAddr& addr) const {
    std::vector<uint8_t> vchGroup = addr.GetGroup();

    // Hash: key + group
    // Concatenate all data into a buffer for one-shot hash
    std::vector<uint8_t> buffer;
    buffer.reserve(32 + vchGroup.size());
    buffer.insert(buffer.end(), nKey.data, nKey.data + 32);
    buffer.insert(buffer.end(), vchGroup.begin(), vchGroup.end());

    uint8_t hash[32];
    SHA3_256(buffer.data(), buffer.size(), hash);

    uint64_t hash64;
    std::memcpy(&hash64, hash, 8);

    return static_cast<int>(hash64 % ADDRMAN_TRIED_BUCKET_COUNT);
}

int CAddrMan::GetBucketPosition(const CNetAddr& addr, bool fNew, int nBucket) const {
    // Hash: key + bucket + address
    // Concatenate all data into a buffer for one-shot hash
    std::vector<uint8_t> buffer;
    buffer.reserve(32 + 1 + 4 + 16);
    buffer.insert(buffer.end(), nKey.data, nKey.data + 32);

    uint8_t fNewByte = fNew ? 1 : 0;
    buffer.push_back(fNewByte);

    int32_t nBucket32 = nBucket;
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&nBucket32),
                  reinterpret_cast<const uint8_t*>(&nBucket32) + 4);

    const uint8_t* addrBytes = addr.GetAddrBytes();
    buffer.insert(buffer.end(), addrBytes, addrBytes + 16);

    uint8_t hash[32];
    SHA3_256(buffer.data(), buffer.size(), hash);

    uint64_t hash64;
    std::memcpy(&hash64, hash, 8);

    return static_cast<int>(hash64 % ADDRMAN_BUCKET_SIZE);
}

bool CAddrMan::Add(const CNetworkAddr& addr, const CNetAddr& source, int64_t nTimePenalty) {
    std::lock_guard<std::mutex> lock(cs);

    // Validate address
    if (!addr.IsRoutable()) {
        return false;
    }

    // Check if already exists
    CAddrInfo* pinfo = Find(addr);

    if (pinfo) {
        // Update timestamp if newer
        bool fCurrentlyOnline = (GetAdjustedTime() - addr.nTime < 24 * 60 * 60);
        int64_t nUpdateInterval = fCurrentlyOnline ? (60 * 60) : (24 * 60 * 60);

        if (addr.nTime && (!pinfo->nTime || pinfo->nTime < addr.nTime - nUpdateInterval - nTimePenalty)) {
            pinfo->nTime = std::max((int64_t)0, addr.nTime - nTimePenalty);
        }

        // Update services
        pinfo->nServices = addr.nServices | pinfo->nServices;

        // Do not update if already in tried
        if (pinfo->fInTried) return false;
        if (pinfo->nRefCount == ADDRMAN_NEW_BUCKETS_PER_ADDRESS) return false;

        // Calculate bucket and check if already there
        int nBucket = GetNewBucket(addr, source);
        int nBucketPos = GetBucketPosition(addr, true, nBucket);

        if (vvNew[nBucket][nBucketPos] != -1) {
            auto itExisting = mapAddr.find(addr);
            if (itExisting != mapAddr.end() && vvNew[nBucket][nBucketPos] == itExisting->second) {
                return false;  // Already in this bucket
            }
        }

        // Add to bucket
        ClearNew(nBucket, nBucketPos);

        auto itAddr = mapAddr.find(addr);
        if (itAddr != mapAddr.end()) {
            vvNew[nBucket][nBucketPos] = itAddr->second;
            pinfo->nRefCount++;
        }

        return true;
    } else {
        // Create new entry
        int nId;
        Create(addr, source, &nId);

        mapInfo[nId].nTime = std::max((int64_t)0, addr.nTime - nTimePenalty);
        mapInfo[nId].nServices = addr.nServices;

        // Add to new table
        int nBucket = GetNewBucket(addr, source);
        int nBucketPos = GetBucketPosition(addr, true, nBucket);

        ClearNew(nBucket, nBucketPos);
        vvNew[nBucket][nBucketPos] = nId;
        mapInfo[nId].nRefCount++;
        nNew++;

        return true;
    }
}

int CAddrMan::Add(const std::vector<CNetworkAddr>& vAddr, const CNetAddr& source, int64_t nTimePenalty) {
    int nAdd = 0;
    for (const CNetworkAddr& addr : vAddr) {
        if (Add(addr, source, nTimePenalty)) {
            nAdd++;
        }
    }
    return nAdd;
}

void CAddrMan::Good(const CService& addr, int64_t nTime) {
    std::lock_guard<std::mutex> lock(cs);

    if (nTime == 0) {
        nTime = GetAdjustedTime();
    }

    CAddrInfo* pinfo = Find(addr);
    if (!pinfo) return;

    auto itAddr = mapAddr.find(addr);
    if (itAddr == mapAddr.end()) return;

    int nId = itAddr->second;
    CAddrInfo& info = mapInfo[nId];

    // Update success info
    info.nLastSuccess = nTime;
    info.nLastTry = nTime;
    info.nAttempts = 0;
    info.nTime = nTime;

    // If already in tried, nothing more to do
    if (info.fInTried) return;

    // Move to tried table
    MakeTried(info, nId);
}

void CAddrMan::Attempt(const CService& addr, bool fCountFailure, int64_t nTime) {
    std::lock_guard<std::mutex> lock(cs);

    if (nTime == 0) {
        nTime = GetAdjustedTime();
    }

    CAddrInfo* pinfo = Find(addr);
    if (!pinfo) return;

    pinfo->nLastTry = nTime;

    if (fCountFailure && pinfo->nLastCountAttempt < nTime - 60 * 60) {
        pinfo->nLastCountAttempt = nTime;
        pinfo->nAttempts++;
    }
}

std::pair<CNetworkAddr, int64_t> CAddrMan::Select(bool newOnly) const {
    std::lock_guard<std::mutex> lock(cs);

    if (vRandom.empty()) {
        return std::make_pair(CNetworkAddr(), 0);
    }

    // 50% chance of tried vs new (unless newOnly)
    bool fChanceTried = !newOnly && (nTried > 0) && (nNew == 0 || (insecure_rand() % 2 == 0));

    // BUG #145 FIX: Add maximum iteration count to prevent infinite loops
    // If all bucket slots are empty (inconsistent state), the while(true) would spin forever
    constexpr int MAX_SELECT_ITERATIONS = 10000;

    if (fChanceTried) {
        // Select from tried table
        double fChanceFactor = 1.0;
        int64_t nNow = GetAdjustedTime();

        for (int iterations = 0; iterations < MAX_SELECT_ITERATIONS; ++iterations) {
            // Random bucket
            int nKBucket = insecure_rand() % ADDRMAN_TRIED_BUCKET_COUNT;
            int nKBucketPos = insecure_rand() % ADDRMAN_BUCKET_SIZE;

            if (vvTried[nKBucket][nKBucketPos] == -1) continue;

            int nId = vvTried[nKBucket][nKBucketPos];
            auto it = mapInfo.find(nId);
            if (it == mapInfo.end()) continue;

            const CAddrInfo& info = it->second;

            // Check if selected
            if ((insecure_rand() % (1 << 30)) < fChanceFactor * info.GetChance(nNow) * (1 << 30)) {
                return std::make_pair(info, info.nLastTry);
            }

            fChanceFactor *= 1.2;
        }
        // Max iterations reached - return empty to prevent infinite loop
        return std::make_pair(CNetworkAddr(), 0);
    } else {
        // Select from new table
        double fChanceFactor = 1.0;
        int64_t nNow = GetAdjustedTime();

        for (int iterations = 0; iterations < MAX_SELECT_ITERATIONS; ++iterations) {
            int nUBucket = insecure_rand() % ADDRMAN_NEW_BUCKET_COUNT;
            int nUBucketPos = insecure_rand() % ADDRMAN_BUCKET_SIZE;

            if (vvNew[nUBucket][nUBucketPos] == -1) continue;

            int nId = vvNew[nUBucket][nUBucketPos];
            auto it = mapInfo.find(nId);
            if (it == mapInfo.end()) continue;

            const CAddrInfo& info = it->second;

            if ((insecure_rand() % (1 << 30)) < fChanceFactor * info.GetChance(nNow) * (1 << 30)) {
                return std::make_pair(info, info.nLastTry);
            }

            fChanceFactor *= 1.2;
        }
        // Max iterations reached - return empty to prevent infinite loop
        return std::make_pair(CNetworkAddr(), 0);
    }

    // BUG #145 FIX: Now unreachable since both branches explicitly return after max iterations
    return std::make_pair(CNetworkAddr(), 0);
}

std::vector<CNetworkAddr> CAddrMan::GetAddr(size_t maxAddresses, size_t maxPct) const {
    std::lock_guard<std::mutex> lock(cs);

    std::vector<CNetworkAddr> vAddr;

    size_t nNodes = vRandom.size();
    if (nNodes == 0) return vAddr;

    // Calculate how many to return
    size_t nCount = std::min(maxAddresses, nNodes * maxPct / 100);
    nCount = std::min(nCount, nNodes);

    if (nCount == 0) return vAddr;

    // Random selection
    std::vector<int> vShuffled = vRandom;
    for (size_t i = 0; i < nCount; i++) {
        size_t nSwap = i + (insecure_rand() % (vShuffled.size() - i));
        std::swap(vShuffled[i], vShuffled[nSwap]);
    }

    // Build result
    int64_t nNow = GetAdjustedTime();
    for (size_t i = 0; i < nCount; i++) {
        auto it = mapInfo.find(vShuffled[i]);
        if (it == mapInfo.end()) continue;

        const CAddrInfo& info = it->second;

        // Don't return terrible addresses
        if (info.IsTerrible(nNow)) continue;

        vAddr.push_back(info);
    }

    return vAddr;
}

size_t CAddrMan::Size() const {
    std::lock_guard<std::mutex> lock(cs);
    return mapInfo.size();
}

void CAddrMan::Clear() {
    std::lock_guard<std::mutex> lock(cs);
    ClearLocked();
}

void CAddrMan::ClearLocked() {
    // Note: Caller must hold cs lock

    mapInfo.clear();
    mapAddr.clear();
    vRandom.clear();

    nIdCount = 0;
    nNew = 0;
    nTried = 0;

    // Reinitialize buckets
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            vvNew[bucket][i] = -1;
        }
    }

    for (int bucket = 0; bucket < ADDRMAN_TRIED_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            vvTried[bucket][i] = -1;
        }
    }
}

void CAddrMan::GetStats(int& nNewOut, int& nTriedOut) const {
    std::lock_guard<std::mutex> lock(cs);
    nNewOut = nNew;
    nTriedOut = nTried;
}

std::string CAddrMan::GetBucketStats() const {
    std::lock_guard<std::mutex> lock(cs);

    std::ostringstream ss;
    ss << "AddrMan Statistics:\n";
    ss << "  Total addresses: " << mapInfo.size() << "\n";
    ss << "  New table entries: " << nNew << "\n";
    ss << "  Tried table entries: " << nTried << "\n";

    // Count non-empty buckets
    int nNewBucketsUsed = 0;
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (vvNew[bucket][i] != -1) {
                nNewBucketsUsed++;
                break;
            }
        }
    }

    int nTriedBucketsUsed = 0;
    for (int bucket = 0; bucket < ADDRMAN_TRIED_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (vvTried[bucket][i] != -1) {
                nTriedBucketsUsed++;
                break;
            }
        }
    }

    ss << "  New buckets used: " << nNewBucketsUsed << "/" << ADDRMAN_NEW_BUCKET_COUNT << "\n";
    ss << "  Tried buckets used: " << nTriedBucketsUsed << "/" << ADDRMAN_TRIED_BUCKET_COUNT << "\n";

    return ss.str();
}

void CAddrMan::Check() const {
    // Debug consistency check - expensive, use only for testing
    std::lock_guard<std::mutex> lock(cs);

    int nNewCount = 0;
    int nTriedCount = 0;

    // Count new table entries
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (vvNew[bucket][i] != -1) {
                nNewCount++;
            }
        }
    }

    // Count tried table entries
    for (int bucket = 0; bucket < ADDRMAN_TRIED_BUCKET_COUNT; bucket++) {
        for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
            if (vvTried[bucket][i] != -1) {
                nTriedCount++;
            }
        }
    }

    // Note: nNewCount may be > nNew due to same address in multiple buckets
    assert(nTriedCount == nTried);
}

//-----------------------------------------------------------------------------
// File persistence (peers.dat)
//-----------------------------------------------------------------------------

/**
 * Simple file stream wrapper for serialization compatibility
 */
class CFileStream {
public:
    std::fstream file;

    CFileStream(const std::string& path, std::ios_base::openmode mode) {
        file.open(path, mode | std::ios::binary);
    }

    ~CFileStream() {
        if (file.is_open()) {
            file.close();
        }
    }

    bool is_open() const { return file.is_open(); }
    bool good() const { return file.good(); }

    void write(const char* data, size_t len) {
        file.write(data, len);
    }

    void read(char* data, size_t len) {
        file.read(data, len);
    }
};

bool CAddrMan::SaveToFile(const std::string& path) const {
    // Write to temp file first, then rename (atomic on most filesystems)
    std::string temp_path = path + ".new";

    try {
        CFileStream stream(temp_path, std::ios::out | std::ios::trunc);
        if (!stream.is_open()) {
            return false;
        }

        Serialize(stream);

        if (!stream.good()) {
            return false;
        }

        stream.file.close();

        // Rename temp file to final path (atomic)
        // On Windows, need to remove existing file first
        // CID 1675210 FIX: Check return value of std::remove to ensure old file is removed
        // std::remove returns 0 on success, non-zero on error
        // On Windows, we need to remove the old file before rename (rename doesn't replace existing files)
        // If file doesn't exist, remove will fail but that's okay - we just want to ensure it's gone
#ifdef _WIN32
        if (std::remove(path.c_str()) != 0) {
            // File might not exist (first save) - that's okay, but check for actual errors
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                // Actual error (not just "file doesn't exist") - log warning but continue
                // This is non-fatal - rename might still work if file doesn't exist
                std::cerr << "[AddrMan] Warning: Failed to remove old peers file: " << path
                          << " (error: " << error << ")" << std::endl;
            }
        }
#endif
        if (std::rename(temp_path.c_str(), path.c_str()) != 0) {
            // CID 1675210 FIX: Best-effort cleanup - remove temp file (errors are non-critical here)
            (void)std::remove(temp_path.c_str());
            return false;
        }

        return true;

    } catch (...) {
        // CID 1675210 FIX: Best-effort cleanup - remove temp file (errors are non-critical here)
        (void)std::remove(temp_path.c_str());
        return false;
    }
}

bool CAddrMan::LoadFromFile(const std::string& path) {
    try {
        CFileStream stream(path, std::ios::in);
        if (!stream.is_open()) {
            // File doesn't exist - this is OK, start with empty AddrMan
            return true;
        }

        Unserialize(stream);

        return stream.good();

    } catch (...) {
        // Error loading file - clear and start fresh
        Clear();
        return false;
    }
}
