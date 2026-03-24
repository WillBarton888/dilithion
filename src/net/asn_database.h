#ifndef DILITHION_NET_ASN_DATABASE_H
#define DILITHION_NET_ASN_DATABASE_H

#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <mutex>

/**
 * ASN Database — maps IPv4 addresses to Autonomous System Numbers.
 *
 * Used by seed nodes to check whether a connecting miner is on a
 * datacenter IP (and refuse MIK attestation if so).
 *
 * Data source: iptoasn.com (ip2asn-v4.tsv)
 * Format: start_ip\tend_ip\tASN\tcountry\tAS_description
 * Example: 1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARE
 *
 * The database is loaded once on startup.  The datacenter ASN list
 * is a separate text file (one ASN per line) that can be updated
 * without rebuilding.
 */
class CASNDatabase {
public:
    CASNDatabase() = default;

    /**
     * Load the IP-to-ASN database from a TSV file.
     * @param path  Path to ip2asn-v4.tsv
     * @return true if loaded successfully
     */
    bool LoadDatabase(const std::string& path);

    /**
     * Load the datacenter ASN list from a text file.
     * Format: one ASN number per line (e.g., "396982"), # comments allowed.
     * @param path  Path to datacenter-asns.txt
     * @return true if loaded successfully
     */
    bool LoadDatacenterList(const std::string& path);

    /**
     * Look up the ASN for an IPv4 address.
     * @param ipv4  Dotted-quad string (e.g., "34.51.239.123")
     * @return ASN number, or 0 if not found
     */
    uint32_t LookupASN(const std::string& ipv4) const;

    /**
     * Look up the AS description for an IPv4 address.
     * @param ipv4  Dotted-quad string
     * @return AS description string, or empty if not found
     */
    std::string LookupDescription(const std::string& ipv4) const;

    /**
     * Check if an IPv4 address belongs to a datacenter ASN.
     * @param ipv4  Dotted-quad string
     * @return true if the IP's ASN is in the datacenter list
     */
    bool IsDatacenterIP(const std::string& ipv4) const;

    /** Number of IP ranges loaded. */
    size_t RangeCount() const;

    /** Number of datacenter ASNs loaded. */
    size_t DatacenterASNCount() const;

    /** Check if database is loaded. */
    bool IsLoaded() const { return !m_ranges.empty(); }

private:
    struct IPRange {
        uint32_t start;       // Start IP (host byte order)
        uint32_t end;         // End IP (host byte order)
        uint32_t asn;         // AS number
        std::string description; // AS description
    };

    // Sorted by start IP for binary search
    std::vector<IPRange> m_ranges;

    // Set of datacenter ASN numbers
    std::set<uint32_t> m_datacenterASNs;

    mutable std::mutex m_mutex;

    /** Convert dotted-quad to uint32_t (host byte order). Returns 0 on error. */
    static uint32_t ParseIPv4(const std::string& ip);
};

#endif // DILITHION_NET_ASN_DATABASE_H
