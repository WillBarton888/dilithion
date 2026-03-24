#include "asn_database.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

// ---------------------------------------------------------------------------
// ParseIPv4 — dotted-quad to uint32_t (host byte order)
// ---------------------------------------------------------------------------

uint32_t CASNDatabase::ParseIPv4(const std::string& ip)
{
    uint32_t a, b, c, d;
    char dot1, dot2, dot3;
    std::istringstream iss(ip);
    if (!(iss >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d))
        return 0;
    if (dot1 != '.' || dot2 != '.' || dot3 != '.')
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// ---------------------------------------------------------------------------
// LoadDatabase — parse ip2asn-v4.tsv
// Format: start_ip\tend_ip\tASN\tcountry\tAS_description
// ---------------------------------------------------------------------------

bool CASNDatabase::LoadDatabase(const std::string& path)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[ASN] Cannot open database: " << path << std::endl;
        return false;
    }

    std::vector<IPRange> ranges;
    ranges.reserve(500000);  // Typical size ~400K ranges

    std::string line;
    int lineNum = 0;
    while (std::getline(file, line)) {
        lineNum++;
        if (line.empty() || line[0] == '#')
            continue;

        // Parse tab-separated fields
        std::istringstream iss(line);
        std::string startIP, endIP, asnStr, country, description;

        if (!std::getline(iss, startIP, '\t')) continue;
        if (!std::getline(iss, endIP, '\t')) continue;
        if (!std::getline(iss, asnStr, '\t')) continue;
        if (!std::getline(iss, country, '\t')) continue;
        std::getline(iss, description);  // May be empty

        uint32_t start = ParseIPv4(startIP);
        uint32_t end = ParseIPv4(endIP);
        uint32_t asn = 0;
        try { asn = static_cast<uint32_t>(std::stoul(asnStr)); }
        catch (...) { continue; }

        if (start == 0 && end == 0) continue;
        if (asn == 0) continue;  // "Not routed" entries

        ranges.push_back({start, end, asn, std::move(description)});
    }

    // Sort by start IP for binary search
    std::sort(ranges.begin(), ranges.end(),
        [](const IPRange& a, const IPRange& b) { return a.start < b.start; });

    std::lock_guard<std::mutex> lock(m_mutex);
    m_ranges = std::move(ranges);

    std::cout << "[ASN] Loaded " << m_ranges.size() << " IP ranges from " << path << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// LoadDatacenterList — parse datacenter-asns.txt
// Format: one ASN number per line, # comments
// ---------------------------------------------------------------------------

bool CASNDatabase::LoadDatacenterList(const std::string& path)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[ASN] Cannot open datacenter list: " << path << std::endl;
        return false;
    }

    std::set<uint32_t> asns;
    std::string line;
    while (std::getline(file, line)) {
        // Strip comments and whitespace
        auto commentPos = line.find('#');
        if (commentPos != std::string::npos)
            line = line.substr(0, commentPos);

        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        size_t end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);

        if (line.empty()) continue;

        // Strip "AS" prefix if present (e.g., "AS396982" → "396982")
        if (line.size() > 2 && (line[0] == 'A' || line[0] == 'a') &&
            (line[1] == 'S' || line[1] == 's')) {
            line = line.substr(2);
        }

        try {
            uint32_t asn = static_cast<uint32_t>(std::stoul(line));
            if (asn > 0) asns.insert(asn);
        } catch (...) {
            continue;
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_datacenterASNs = std::move(asns);

    std::cout << "[ASN] Loaded " << m_datacenterASNs.size() << " datacenter ASNs from " << path << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// LookupASN — binary search for IP in sorted ranges
// ---------------------------------------------------------------------------

uint32_t CASNDatabase::LookupASN(const std::string& ipv4) const
{
    uint32_t ip = ParseIPv4(ipv4);
    if (ip == 0) return 0;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_ranges.empty()) return 0;

    // Binary search: find the last range where start <= ip
    auto it = std::upper_bound(m_ranges.begin(), m_ranges.end(), ip,
        [](uint32_t val, const IPRange& range) { return val < range.start; });

    if (it == m_ranges.begin()) return 0;
    --it;

    // Check if ip falls within [start, end]
    if (ip >= it->start && ip <= it->end)
        return it->asn;

    return 0;
}

// ---------------------------------------------------------------------------
// LookupDescription
// ---------------------------------------------------------------------------

std::string CASNDatabase::LookupDescription(const std::string& ipv4) const
{
    uint32_t ip = ParseIPv4(ipv4);
    if (ip == 0) return "";

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_ranges.empty()) return "";

    auto it = std::upper_bound(m_ranges.begin(), m_ranges.end(), ip,
        [](uint32_t val, const IPRange& range) { return val < range.start; });

    if (it == m_ranges.begin()) return "";
    --it;

    if (ip >= it->start && ip <= it->end)
        return it->description;

    return "";
}

// ---------------------------------------------------------------------------
// IsDatacenterIP — lookup ASN and check against datacenter list
// ---------------------------------------------------------------------------

bool CASNDatabase::IsDatacenterIP(const std::string& ipv4) const
{
    uint32_t asn = LookupASN(ipv4);
    if (asn == 0) return false;  // Unknown = not datacenter (fail-open)

    std::lock_guard<std::mutex> lock(m_mutex);
    return m_datacenterASNs.count(asn) > 0;
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

size_t CASNDatabase::RangeCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_ranges.size();
}

size_t CASNDatabase::DatacenterASNCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_datacenterASNs.size();
}
