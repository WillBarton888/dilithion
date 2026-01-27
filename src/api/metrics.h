// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_API_METRICS_H
#define DILITHION_API_METRICS_H

#include <atomic>
#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <map>

/**
 * CNodeMetrics - Comprehensive metrics collection for Prometheus/Grafana monitoring
 *
 * Provides thread-safe counters and gauges for:
 * - Node health (block height, peers, uptime)
 * - Network activity (messages, bandwidth)
 * - Consensus (blocks, reorgs, orphans)
 * - Attack detection (invalid blocks, bans, spam)
 * - Performance (validation times)
 */
class CNodeMetrics {
public:
    // Singleton access
    static CNodeMetrics& Instance() {
        static CNodeMetrics instance;
        return instance;
    }

    // ============================================
    // Node Health Metrics
    // ============================================
    std::atomic<int64_t> block_height{0};
    std::atomic<int64_t> headers_height{0};
    std::atomic<int64_t> peer_count{0};
    std::atomic<int64_t> inbound_peers{0};
    std::atomic<int64_t> outbound_peers{0};
    std::atomic<int64_t> mempool_size{0};
    std::atomic<int64_t> mempool_bytes{0};
    std::chrono::steady_clock::time_point start_time;

    // ============================================
    // Mining Metrics
    // ============================================
    std::atomic<int64_t> mining_active{0};      // 1 if mining, 0 if not
    std::atomic<uint64_t> hashrate{0};          // Current hashrate in H/s
    std::atomic<uint64_t> hashes_total{0};      // Total hashes computed
    std::atomic<uint64_t> blocks_mined{0};      // Total blocks mined by this node

    // ============================================
    // Network Activity Counters
    // ============================================
    std::atomic<uint64_t> messages_received_total{0};
    std::atomic<uint64_t> messages_sent_total{0};
    std::atomic<uint64_t> bytes_received_total{0};
    std::atomic<uint64_t> bytes_sent_total{0};

    // Message type counters (received)
    std::atomic<uint64_t> msg_block_received{0};
    std::atomic<uint64_t> msg_tx_received{0};
    std::atomic<uint64_t> msg_headers_received{0};
    std::atomic<uint64_t> msg_inv_received{0};
    std::atomic<uint64_t> msg_getdata_received{0};
    std::atomic<uint64_t> msg_getblocks_received{0};
    std::atomic<uint64_t> msg_getheaders_received{0};
    std::atomic<uint64_t> msg_ping_received{0};
    std::atomic<uint64_t> msg_pong_received{0};
    std::atomic<uint64_t> msg_addr_received{0};
    std::atomic<uint64_t> msg_version_received{0};

    // ============================================
    // Consensus & Sync Metrics
    // ============================================
    std::atomic<uint64_t> blocks_validated_total{0};
    std::atomic<uint64_t> blocks_accepted_total{0};
    std::atomic<uint64_t> blocks_relayed_total{0};
    std::atomic<uint64_t> reorgs_total{0};
    std::atomic<uint64_t> orphan_blocks_total{0};
    std::atomic<int64_t> ibd_progress_percent{0};  // 0-100
    std::atomic<int64_t> blocks_in_flight{0};
    std::atomic<int64_t> last_block_time{0};  // Unix timestamp

    // ============================================
    // Attack Detection Metrics (CRITICAL)
    // ============================================
    std::atomic<uint64_t> invalid_blocks_total{0};
    std::atomic<uint64_t> invalid_headers_total{0};
    std::atomic<uint64_t> invalid_transactions_total{0};
    std::atomic<uint64_t> peer_bans_total{0};
    std::atomic<uint64_t> duplicate_messages_total{0};
    std::atomic<uint64_t> connection_attempts_total{0};
    std::atomic<uint64_t> connection_rejected_total{0};
    std::atomic<uint64_t> dos_score_exceeded_total{0};
    std::atomic<int64_t> fork_detected{0};  // 1 if fork detected, 0 otherwise
    std::atomic<int64_t> fork_depth{0};      // Depth of detected fork (blocks behind)
    std::atomic<int64_t> fork_point_height{0}; // Height where fork diverged

    // ============================================
    // Performance Metrics
    // ============================================
    std::atomic<uint64_t> block_validation_time_ms{0};  // Last block validation time
    std::atomic<uint64_t> header_sync_rate{0};  // Headers synced per second
    std::atomic<uint64_t> tx_validation_time_us{0};  // Last tx validation time

    // ============================================
    // Orphan Pool Metrics (Phase 2 Stress Test)
    // ============================================
    std::atomic<int64_t> orphan_pool_size{0};           // Current orphan count
    std::atomic<int64_t> orphan_pool_bytes{0};          // Total memory used by orphans
    std::atomic<int64_t> orphan_pool_connectable{0};    // Orphans whose parent exists
    std::atomic<int64_t> orphan_pool_unconnectable{0};  // Orphans whose parent missing
    std::atomic<int64_t> orphan_pool_oldest_age_secs{0}; // Age of oldest orphan in seconds

    // ============================================
    // Validation Queue Metrics (Phase 2 Stress Test)
    // ============================================
    std::atomic<int64_t> validation_queue_depth{0};      // Blocks waiting for validation
    std::atomic<int64_t> validation_processing_ms{0};    // Current block processing time
    std::atomic<int64_t> validation_last_completion{0};  // Unix timestamp of last completion

    // ============================================
    // Parent Request Metrics (Phase 2 Stress Test)
    // ============================================
    std::atomic<int64_t> parent_requests_pending{0};     // Pending parent requests
    std::atomic<uint64_t> parent_requests_timeout{0};    // Parent requests that timed out
    std::atomic<uint64_t> parent_requests_success{0};    // Parent requests that succeeded

    // ============================================
    // Helper Methods
    // ============================================

    // Record a message received
    void RecordMessageReceived(const std::string& msg_type, size_t bytes) {
        messages_received_total++;
        bytes_received_total += bytes;

        if (msg_type == "block") msg_block_received++;
        else if (msg_type == "tx") msg_tx_received++;
        else if (msg_type == "headers") msg_headers_received++;
        else if (msg_type == "inv") msg_inv_received++;
        else if (msg_type == "getdata") msg_getdata_received++;
        else if (msg_type == "getblocks") msg_getblocks_received++;
        else if (msg_type == "getheaders") msg_getheaders_received++;
        else if (msg_type == "ping") msg_ping_received++;
        else if (msg_type == "pong") msg_pong_received++;
        else if (msg_type == "addr") msg_addr_received++;
        else if (msg_type == "version") msg_version_received++;
    }

    void RecordMessageSent(size_t bytes) {
        messages_sent_total++;
        bytes_sent_total += bytes;
    }

    void RecordInvalidBlock() {
        invalid_blocks_total++;
    }

    void RecordInvalidHeader() {
        invalid_headers_total++;
    }

    void RecordPeerBan() {
        peer_bans_total++;
    }

    void RecordReorg() {
        reorgs_total++;
    }

    void RecordOrphanBlock() {
        orphan_blocks_total++;
    }

    void RecordConnectionAttempt(bool accepted) {
        connection_attempts_total++;
        if (!accepted) connection_rejected_total++;
    }

    void SetForkDetected(bool detected, int64_t depth = 0, int64_t forkPointHeight = 0) {
        fork_detected.store(detected ? 1 : 0);
        fork_depth.store(depth);
        fork_point_height.store(forkPointHeight);
    }

    void ClearForkDetected() {
        fork_detected.store(0);
        fork_depth.store(0);
        fork_point_height.store(0);
    }

    // Get uptime in seconds
    int64_t GetUptimeSeconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    }

    // Network name for metrics labeling
    std::string network_name{"mainnet"};  // Default to mainnet

    void SetNetworkName(const std::string& name) {
        network_name = name;
    }

    // ============================================
    // Generate Prometheus-format output
    // ============================================
    std::string ToPrometheus() const {
        std::ostringstream out;

        // Common label for all metrics
        std::string net_label = "network=\"" + network_name + "\"";

        // Node info
        out << "# HELP dilithion_info Node information\n";
        out << "# TYPE dilithion_info gauge\n";
        out << "dilithion_info{" << net_label << ",version=\"1.4.0\"} 1\n\n";

        // Uptime
        out << "# HELP dilithion_uptime_seconds Node uptime in seconds\n";
        out << "# TYPE dilithion_uptime_seconds counter\n";
        out << "dilithion_uptime_seconds{" << net_label << "} " << GetUptimeSeconds() << "\n\n";

        // Block height
        out << "# HELP dilithion_block_height Current blockchain height\n";
        out << "# TYPE dilithion_block_height gauge\n";
        out << "dilithion_block_height{" << net_label << "} " << block_height.load() << "\n\n";

        // Headers height
        out << "# HELP dilithion_headers_height Current headers chain height\n";
        out << "# TYPE dilithion_headers_height gauge\n";
        out << "dilithion_headers_height{" << net_label << "} " << headers_height.load() << "\n\n";

        // Peer count
        out << "# HELP dilithion_peer_count Number of connected peers\n";
        out << "# TYPE dilithion_peer_count gauge\n";
        out << "dilithion_peer_count{" << net_label << "} " << peer_count.load() << "\n\n";

        // Inbound peers
        out << "# HELP dilithion_inbound_peers Number of inbound peer connections\n";
        out << "# TYPE dilithion_inbound_peers gauge\n";
        out << "dilithion_inbound_peers{" << net_label << "} " << inbound_peers.load() << "\n\n";

        // Outbound peers
        out << "# HELP dilithion_outbound_peers Number of outbound peer connections\n";
        out << "# TYPE dilithion_outbound_peers gauge\n";
        out << "dilithion_outbound_peers{" << net_label << "} " << outbound_peers.load() << "\n\n";

        // Mining active
        out << "# HELP dilithion_mining_active Mining status (1=active, 0=inactive)\n";
        out << "# TYPE dilithion_mining_active gauge\n";
        out << "dilithion_mining_active{" << net_label << "} " << mining_active.load() << "\n\n";

        // Hashrate
        out << "# HELP dilithion_hashrate Current mining hashrate in H/s\n";
        out << "# TYPE dilithion_hashrate gauge\n";
        out << "dilithion_hashrate{" << net_label << "} " << hashrate.load() << "\n\n";

        // Blocks mined
        out << "# HELP dilithion_blocks_mined Total blocks mined by this node\n";
        out << "# TYPE dilithion_blocks_mined counter\n";
        out << "dilithion_blocks_mined{" << net_label << "} " << blocks_mined.load() << "\n\n";

        // Mempool
        out << "# HELP dilithion_mempool_size Number of transactions in mempool\n";
        out << "# TYPE dilithion_mempool_size gauge\n";
        out << "dilithion_mempool_size{" << net_label << "} " << mempool_size.load() << "\n\n";

        // Messages received by type
        out << "# HELP dilithion_messages_received_total Total messages received by type\n";
        out << "# TYPE dilithion_messages_received_total counter\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"block\"} " << msg_block_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"tx\"} " << msg_tx_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"headers\"} " << msg_headers_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"inv\"} " << msg_inv_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"getdata\"} " << msg_getdata_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"getblocks\"} " << msg_getblocks_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"getheaders\"} " << msg_getheaders_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"ping\"} " << msg_ping_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"pong\"} " << msg_pong_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"addr\"} " << msg_addr_received.load() << "\n";
        out << "dilithion_messages_received_total{" << net_label << ",type=\"version\"} " << msg_version_received.load() << "\n\n";

        // Bandwidth
        out << "# HELP dilithion_bytes_received_total Total bytes received\n";
        out << "# TYPE dilithion_bytes_received_total counter\n";
        out << "dilithion_bytes_received_total{" << net_label << "} " << bytes_received_total.load() << "\n\n";

        out << "# HELP dilithion_bytes_sent_total Total bytes sent\n";
        out << "# TYPE dilithion_bytes_sent_total counter\n";
        out << "dilithion_bytes_sent_total{" << net_label << "} " << bytes_sent_total.load() << "\n\n";

        // Consensus metrics
        out << "# HELP dilithion_blocks_validated_total Total blocks validated\n";
        out << "# TYPE dilithion_blocks_validated_total counter\n";
        out << "dilithion_blocks_validated_total{" << net_label << "} " << blocks_validated_total.load() << "\n\n";

        out << "# HELP dilithion_blocks_accepted_total Total blocks accepted to chain\n";
        out << "# TYPE dilithion_blocks_accepted_total counter\n";
        out << "dilithion_blocks_accepted_total{" << net_label << "} " << blocks_accepted_total.load() << "\n\n";

        out << "# HELP dilithion_blocks_relayed_total Total blocks relayed to peers\n";
        out << "# TYPE dilithion_blocks_relayed_total counter\n";
        out << "dilithion_blocks_relayed_total{" << net_label << "} " << blocks_relayed_total.load() << "\n\n";

        out << "# HELP dilithion_reorgs_total Total chain reorganizations\n";
        out << "# TYPE dilithion_reorgs_total counter\n";
        out << "dilithion_reorgs_total{" << net_label << "} " << reorgs_total.load() << "\n\n";

        out << "# HELP dilithion_orphan_blocks_total Total orphan blocks received\n";
        out << "# TYPE dilithion_orphan_blocks_total counter\n";
        out << "dilithion_orphan_blocks_total{" << net_label << "} " << orphan_blocks_total.load() << "\n\n";

        out << "# HELP dilithion_ibd_progress_percent IBD progress percentage\n";
        out << "# TYPE dilithion_ibd_progress_percent gauge\n";
        out << "dilithion_ibd_progress_percent{" << net_label << "} " << ibd_progress_percent.load() << "\n\n";

        out << "# HELP dilithion_last_block_time Unix timestamp of last block\n";
        out << "# TYPE dilithion_last_block_time gauge\n";
        out << "dilithion_last_block_time{" << net_label << "} " << last_block_time.load() << "\n\n";

        // Attack detection metrics (CRITICAL)
        out << "# HELP dilithion_invalid_blocks_total Invalid blocks received (attack indicator)\n";
        out << "# TYPE dilithion_invalid_blocks_total counter\n";
        out << "dilithion_invalid_blocks_total{" << net_label << "} " << invalid_blocks_total.load() << "\n\n";

        out << "# HELP dilithion_invalid_headers_total Invalid headers received (DoS indicator)\n";
        out << "# TYPE dilithion_invalid_headers_total counter\n";
        out << "dilithion_invalid_headers_total{" << net_label << "} " << invalid_headers_total.load() << "\n\n";

        out << "# HELP dilithion_invalid_transactions_total Invalid transactions received\n";
        out << "# TYPE dilithion_invalid_transactions_total counter\n";
        out << "dilithion_invalid_transactions_total{" << net_label << "} " << invalid_transactions_total.load() << "\n\n";

        out << "# HELP dilithion_peer_bans_total Peers banned for misbehavior\n";
        out << "# TYPE dilithion_peer_bans_total counter\n";
        out << "dilithion_peer_bans_total{" << net_label << "} " << peer_bans_total.load() << "\n\n";

        out << "# HELP dilithion_duplicate_messages_total Duplicate messages received (spam indicator)\n";
        out << "# TYPE dilithion_duplicate_messages_total counter\n";
        out << "dilithion_duplicate_messages_total{" << net_label << "} " << duplicate_messages_total.load() << "\n\n";

        out << "# HELP dilithion_connection_attempts_total Total connection attempts\n";
        out << "# TYPE dilithion_connection_attempts_total counter\n";
        out << "dilithion_connection_attempts_total{" << net_label << "} " << connection_attempts_total.load() << "\n\n";

        out << "# HELP dilithion_connection_rejected_total Rejected connection attempts\n";
        out << "# TYPE dilithion_connection_rejected_total counter\n";
        out << "dilithion_connection_rejected_total{" << net_label << "} " << connection_rejected_total.load() << "\n\n";

        out << "# HELP dilithion_fork_detected Fork detected indicator (eclipse attack)\n";
        out << "# TYPE dilithion_fork_detected gauge\n";
        out << "dilithion_fork_detected{" << net_label << "} " << fork_detected.load() << "\n\n";

        out << "# HELP dilithion_fork_depth Depth of detected fork in blocks\n";
        out << "# TYPE dilithion_fork_depth gauge\n";
        out << "dilithion_fork_depth{" << net_label << "} " << fork_depth.load() << "\n\n";

        out << "# HELP dilithion_fork_point_height Height where fork diverged\n";
        out << "# TYPE dilithion_fork_point_height gauge\n";
        out << "dilithion_fork_point_height{" << net_label << "} " << fork_point_height.load() << "\n\n";

        // Performance metrics
        out << "# HELP dilithion_block_validation_ms Last block validation time in ms\n";
        out << "# TYPE dilithion_block_validation_ms gauge\n";
        out << "dilithion_block_validation_ms{" << net_label << "} " << block_validation_time_ms.load() << "\n\n";

        // Orphan pool metrics (Phase 2 Stress Test)
        out << "# HELP dilithion_orphan_pool_size Current orphan block count\n";
        out << "# TYPE dilithion_orphan_pool_size gauge\n";
        out << "dilithion_orphan_pool_size{" << net_label << "} " << orphan_pool_size.load() << "\n\n";

        out << "# HELP dilithion_orphan_pool_bytes Memory used by orphan blocks\n";
        out << "# TYPE dilithion_orphan_pool_bytes gauge\n";
        out << "dilithion_orphan_pool_bytes{" << net_label << "} " << orphan_pool_bytes.load() << "\n\n";

        out << "# HELP dilithion_orphan_pool_connectable Orphans whose parent exists\n";
        out << "# TYPE dilithion_orphan_pool_connectable gauge\n";
        out << "dilithion_orphan_pool_connectable{" << net_label << "} " << orphan_pool_connectable.load() << "\n\n";

        out << "# HELP dilithion_orphan_pool_unconnectable Orphans whose parent is missing\n";
        out << "# TYPE dilithion_orphan_pool_unconnectable gauge\n";
        out << "dilithion_orphan_pool_unconnectable{" << net_label << "} " << orphan_pool_unconnectable.load() << "\n\n";

        out << "# HELP dilithion_orphan_pool_oldest_age_secs Age of oldest orphan in seconds\n";
        out << "# TYPE dilithion_orphan_pool_oldest_age_secs gauge\n";
        out << "dilithion_orphan_pool_oldest_age_secs{" << net_label << "} " << orphan_pool_oldest_age_secs.load() << "\n\n";

        // Validation queue metrics (Phase 2 Stress Test)
        out << "# HELP dilithion_validation_queue_depth Blocks waiting for validation\n";
        out << "# TYPE dilithion_validation_queue_depth gauge\n";
        out << "dilithion_validation_queue_depth{" << net_label << "} " << validation_queue_depth.load() << "\n\n";

        out << "# HELP dilithion_validation_processing_ms Current block processing time in ms\n";
        out << "# TYPE dilithion_validation_processing_ms gauge\n";
        out << "dilithion_validation_processing_ms{" << net_label << "} " << validation_processing_ms.load() << "\n\n";

        out << "# HELP dilithion_validation_last_completion Unix timestamp of last validation\n";
        out << "# TYPE dilithion_validation_last_completion gauge\n";
        out << "dilithion_validation_last_completion{" << net_label << "} " << validation_last_completion.load() << "\n\n";

        // Parent request metrics (Phase 2 Stress Test)
        out << "# HELP dilithion_parent_requests_pending Pending parent block requests\n";
        out << "# TYPE dilithion_parent_requests_pending gauge\n";
        out << "dilithion_parent_requests_pending{" << net_label << "} " << parent_requests_pending.load() << "\n\n";

        out << "# HELP dilithion_parent_requests_timeout_total Parent requests that timed out\n";
        out << "# TYPE dilithion_parent_requests_timeout_total counter\n";
        out << "dilithion_parent_requests_timeout_total{" << net_label << "} " << parent_requests_timeout.load() << "\n\n";

        out << "# HELP dilithion_parent_requests_success_total Parent requests that succeeded\n";
        out << "# TYPE dilithion_parent_requests_success_total counter\n";
        out << "dilithion_parent_requests_success_total{" << net_label << "} " << parent_requests_success.load() << "\n\n";

        return out.str();
    }

private:
    CNodeMetrics() {
        start_time = std::chrono::steady_clock::now();
    }

    // Non-copyable
    CNodeMetrics(const CNodeMetrics&) = delete;
    CNodeMetrics& operator=(const CNodeMetrics&) = delete;
};

// Global accessor macro for convenience
#define g_metrics CNodeMetrics::Instance()

#endif // DILITHION_API_METRICS_H
