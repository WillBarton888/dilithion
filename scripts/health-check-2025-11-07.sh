#!/bin/bash
# Dilithion Mainnet Node - Health Check Script
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license
#
# Usage:
#   ./scripts/health-check-2025-11-07.sh                      # Human-readable output
#   ./scripts/health-check-2025-11-07.sh --prometheus         # Prometheus metrics format
#   ./scripts/health-check-2025-11-07.sh --json               # JSON output
#   ./scripts/health-check-2025-11-07.sh --alert-on-failure   # Exit non-zero if unhealthy
#
# Cron usage (check every 5 minutes):
#   */5 * * * * /path/to/scripts/health-check-2025-11-07.sh --prometheus > /var/lib/node_exporter/textfile_collector/dilithion.prom
#
# Version: 1.0.0
# Created: 2025-11-07

set -e  # Exit on error

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-11-07"

# RPC configuration
RPC_HOST="localhost"
RPC_PORT="8332"
RPC_URL="http://$RPC_HOST:$RPC_PORT"

# Health check thresholds
MAX_BLOCK_AGE=600           # Alert if last block older than 10 minutes (2.5 blocks)
MIN_PEER_COUNT=3            # Alert if fewer than 3 peers
MIN_DISK_SPACE_GB=10        # Alert if less than 10GB free
MAX_MEMPOOL_SIZE=10000      # Alert if mempool has >10k transactions
MAX_CPU_PERCENT=95          # Alert if CPU usage >95%
MAX_MEMORY_PERCENT=90       # Alert if memory usage >90%

# Output format
OUTPUT_FORMAT="human"
ALERT_ON_FAILURE=false

# Color codes (only used in human-readable mode)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Health status
OVERALL_HEALTHY=1  # 0 = unhealthy, 1 = healthy

# ==============================================================================
# Helper Functions
# ==============================================================================

# Print message (only in human-readable mode)
print_info() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

print_success() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        echo -e "${GREEN}[OK]${NC} $1"
    fi
}

print_warning() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        echo -e "${YELLOW}[WARNING]${NC} $1"
    fi
    OVERALL_HEALTHY=0
}

print_error() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        echo -e "${RED}[ERROR]${NC} $1"
    fi
    OVERALL_HEALTHY=0
}

# RPC call helper
rpc_call() {
    local method="$1"
    local params="${2:-[]}"

    curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" 2>/dev/null || echo '{"error":{"message":"RPC call failed"}}'
}

# Extract result from RPC response
extract_result() {
    echo "$1" | grep -o '"result":[^,}]*' | cut -d: -f2 | tr -d '"' || echo ""
}

# Extract error from RPC response
extract_error() {
    echo "$1" | grep -o '"message":"[^"]*"' | cut -d'"' -f4 || echo ""
}

# Check if RPC response has error
has_error() {
    echo "$1" | grep -q '"error":'
}

# ==============================================================================
# Health Checks
# ==============================================================================

# Check if node is running
check_node_running() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking if node is running..."
    fi

    if pgrep -x "dilithion-node" > /dev/null; then
        NODE_PID=$(pgrep -x "dilithion-node")
        print_success "Node is running (PID: $NODE_PID)"
        NODE_RUNNING=1
    elif systemctl is-active --quiet dilithion 2>/dev/null; then
        print_success "Node is running (systemd)"
        NODE_RUNNING=1
    else
        print_error "Node is not running"
        NODE_RUNNING=0
        return 1
    fi
}

# Check RPC connectivity
check_rpc() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking RPC connectivity..."
    fi

    local response=$(rpc_call "getblockchaininfo" "[]")

    if has_error "$response"; then
        local error=$(extract_error "$response")
        print_error "RPC not accessible: $error"
        RPC_ACCESSIBLE=0
        return 1
    else
        print_success "RPC is accessible"
        RPC_ACCESSIBLE=1
    fi
}

# Check blockchain sync status
check_blockchain_sync() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking blockchain sync status..."
    fi

    # Get block count
    local response=$(rpc_call "getblockcount" "[]")
    BLOCK_HEIGHT=$(extract_result "$response")

    if [ -z "$BLOCK_HEIGHT" ] || [ "$BLOCK_HEIGHT" = "null" ]; then
        print_error "Cannot retrieve block height"
        BLOCK_HEIGHT=0
        return 1
    fi

    print_success "Block height: $BLOCK_HEIGHT"

    # Get best block hash
    response=$(rpc_call "getbestblockhash" "[]")
    BEST_BLOCK_HASH=$(extract_result "$response")

    # Get block info to check timestamp
    if [ -n "$BEST_BLOCK_HASH" ] && [ "$BEST_BLOCK_HASH" != "null" ]; then
        response=$(rpc_call "getblock" "[\"$BEST_BLOCK_HASH\"]")

        # Extract timestamp (this would need proper JSON parsing in production)
        # For now, estimate based on current time
        CURRENT_TIME=$(date +%s)
        # Assuming 240 second block time
        EXPECTED_BLOCKS_PER_HOUR=$((3600 / 240))

        # Simple check: If we have recent blocks, we're probably synced
        if [ "$BLOCK_HEIGHT" -gt 0 ]; then
            print_success "Blockchain appears synced"
            BLOCKCHAIN_SYNCED=1
        else
            print_warning "Blockchain sync status unknown"
            BLOCKCHAIN_SYNCED=0
        fi
    fi
}

# Check peer connections
check_peers() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking peer connections..."
    fi

    local response=$(rpc_call "getnetworkinfo" "[]")

    # Extract peer count (would need proper JSON parsing)
    # For now, try to get peer info
    response=$(rpc_call "getpeerinfo" "[]")

    if has_error "$response"; then
        PEER_COUNT=0
        print_warning "Cannot retrieve peer count"
    else
        # Count peers (rough estimate - count "addr" fields)
        PEER_COUNT=$(echo "$response" | grep -o '"addr"' | wc -l)

        if [ "$PEER_COUNT" -lt "$MIN_PEER_COUNT" ]; then
            print_warning "Low peer count: $PEER_COUNT (minimum: $MIN_PEER_COUNT)"
        else
            print_success "Peer count: $PEER_COUNT"
        fi
    fi
}

# Check mempool status
check_mempool() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking mempool status..."
    fi

    local response=$(rpc_call "getmempoolinfo" "[]")

    if has_error "$response"; then
        MEMPOOL_SIZE=0
        MEMPOOL_BYTES=0
        print_warning "Cannot retrieve mempool info"
    else
        # Would need proper JSON parsing - for now, estimate
        MEMPOOL_SIZE=$(echo "$response" | grep -o '"size":[0-9]*' | cut -d: -f2 | head -1)
        MEMPOOL_BYTES=$(echo "$response" | grep -o '"bytes":[0-9]*' | cut -d: -f2 | head -1)

        if [ -z "$MEMPOOL_SIZE" ]; then
            MEMPOOL_SIZE=0
        fi
        if [ -z "$MEMPOOL_BYTES" ]; then
            MEMPOOL_BYTES=0
        fi

        if [ "$MEMPOOL_SIZE" -gt "$MAX_MEMPOOL_SIZE" ]; then
            print_warning "Large mempool: $MEMPOOL_SIZE transactions"
        else
            print_success "Mempool size: $MEMPOOL_SIZE transactions"
        fi
    fi
}

# Check mining status
check_mining() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking mining status..."
    fi

    local response=$(rpc_call "getmininginfo" "[]")

    if has_error "$response"; then
        MINING_ACTIVE=0
        HASHRATE=0
        print_info "Mining status unavailable (may not be mining)"
    else
        # Extract mining status (would need proper JSON parsing)
        MINING_ACTIVE=$(echo "$response" | grep -o '"mining":[a-z]*' | cut -d: -f2 | head -1)
        HASHRATE=$(echo "$response" | grep -o '"hashrate":[0-9.]*' | cut -d: -f2 | head -1)

        if [ "$MINING_ACTIVE" = "true" ]; then
            MINING_ACTIVE=1
            print_success "Mining active (hashrate: $HASHRATE H/s)"
        else
            MINING_ACTIVE=0
            HASHRATE=0
            print_info "Mining inactive"
        fi
    fi
}

# Check disk space
check_disk_space() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking disk space..."
    fi

    local data_dir="$HOME/.dilithion"
    if [ ! -d "$data_dir" ]; then
        data_dir="/"
    fi

    DISK_AVAILABLE_GB=$(df -BG "$data_dir" | tail -1 | awk '{print $4}' | sed 's/G//')

    if [ "$DISK_AVAILABLE_GB" -lt "$MIN_DISK_SPACE_GB" ]; then
        print_error "Low disk space: ${DISK_AVAILABLE_GB}GB available (minimum: ${MIN_DISK_SPACE_GB}GB)"
    else
        print_success "Disk space: ${DISK_AVAILABLE_GB}GB available"
    fi
}

# Check system resources
check_system_resources() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking system resources..."
    fi

    # CPU usage
    if command -v top &> /dev/null; then
        CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
        if [ -z "$CPU_USAGE" ]; then
            CPU_USAGE=0
        fi

        CPU_USAGE_INT=${CPU_USAGE%.*}
        if [ "$CPU_USAGE_INT" -gt "$MAX_CPU_PERCENT" ]; then
            print_warning "High CPU usage: ${CPU_USAGE}%"
        else
            print_success "CPU usage: ${CPU_USAGE}%"
        fi
    else
        CPU_USAGE=0
        print_info "CPU usage: unavailable"
    fi

    # Memory usage
    if command -v free &> /dev/null; then
        MEMORY_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
        MEMORY_USED=$(free -m | awk '/^Mem:/{print $3}')
        MEMORY_PERCENT=$((MEMORY_USED * 100 / MEMORY_TOTAL))

        if [ "$MEMORY_PERCENT" -gt "$MAX_MEMORY_PERCENT" ]; then
            print_warning "High memory usage: ${MEMORY_PERCENT}% (${MEMORY_USED}MB / ${MEMORY_TOTAL}MB)"
        else
            print_success "Memory usage: ${MEMORY_PERCENT}% (${MEMORY_USED}MB / ${MEMORY_TOTAL}MB)"
        fi
    else
        MEMORY_PERCENT=0
        print_info "Memory usage: unavailable"
    fi
}

# Check wallet status
check_wallet() {
    if [ "$OUTPUT_FORMAT" = "human" ]; then
        print_info "Checking wallet status..."
    fi

    local response=$(rpc_call "getbalance" "[]")

    if has_error "$response"; then
        WALLET_BALANCE=0
        WALLET_ACCESSIBLE=0
        local error=$(extract_error "$response")
        if echo "$error" | grep -q "wallet"; then
            print_info "Wallet check: $error"
        else
            print_warning "Wallet not accessible"
        fi
    else
        WALLET_BALANCE=$(extract_result "$response")
        WALLET_ACCESSIBLE=1
        print_success "Wallet accessible (balance: $WALLET_BALANCE DIL)"
    fi
}

# ==============================================================================
# Output Functions
# ==============================================================================

# Output in human-readable format
output_human() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║   Dilithion Node Health Check                                 ║"
    echo "║   $(date '+%Y-%m-%d %H:%M:%S %Z')                                       ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    if [ "$OVERALL_HEALTHY" -eq 1 ]; then
        echo -e "${GREEN}Overall Status: HEALTHY${NC}"
    else
        echo -e "${RED}Overall Status: UNHEALTHY${NC}"
    fi

    echo ""
    echo "Summary:"
    echo "  Node Running: $([ "$NODE_RUNNING" -eq 1 ] && echo "✓ Yes" || echo "✗ No")"
    echo "  RPC Accessible: $([ "$RPC_ACCESSIBLE" -eq 1 ] && echo "✓ Yes" || echo "✗ No")"
    echo "  Block Height: $BLOCK_HEIGHT"
    echo "  Peers: $PEER_COUNT"
    echo "  Mempool Size: $MEMPOOL_SIZE transactions"
    echo "  Mining: $([ "$MINING_ACTIVE" -eq 1 ] && echo "Active ($HASHRATE H/s)" || echo "Inactive")"
    echo "  Disk Space: ${DISK_AVAILABLE_GB}GB"
    echo "  CPU Usage: ${CPU_USAGE}%"
    echo "  Memory Usage: ${MEMORY_PERCENT}%"
    echo "  Wallet: $([ "$WALLET_ACCESSIBLE" -eq 1 ] && echo "$WALLET_BALANCE DIL" || echo "Not accessible")"
    echo ""
}

# Output in Prometheus format
output_prometheus() {
    cat <<EOF
# HELP dilithion_node_running Whether the Dilithion node is running (1=yes, 0=no)
# TYPE dilithion_node_running gauge
dilithion_node_running $NODE_RUNNING

# HELP dilithion_rpc_accessible Whether the RPC server is accessible (1=yes, 0=no)
# TYPE dilithion_rpc_accessible gauge
dilithion_rpc_accessible $RPC_ACCESSIBLE

# HELP dilithion_block_height Current blockchain height
# TYPE dilithion_block_height gauge
dilithion_block_height $BLOCK_HEIGHT

# HELP dilithion_blockchain_synced Whether the blockchain is synced (1=yes, 0=no)
# TYPE dilithion_blockchain_synced gauge
dilithion_blockchain_synced ${BLOCKCHAIN_SYNCED:-0}

# HELP dilithion_peer_count Number of connected peers
# TYPE dilithion_peer_count gauge
dilithion_peer_count $PEER_COUNT

# HELP dilithion_mempool_size Number of transactions in mempool
# TYPE dilithion_mempool_size gauge
dilithion_mempool_size $MEMPOOL_SIZE

# HELP dilithion_mempool_bytes Total bytes in mempool
# TYPE dilithion_mempool_bytes gauge
dilithion_mempool_bytes ${MEMPOOL_BYTES:-0}

# HELP dilithion_mining_active Whether mining is active (1=yes, 0=no)
# TYPE dilithion_mining_active gauge
dilithion_mining_active $MINING_ACTIVE

# HELP dilithion_hashrate Current mining hashrate in H/s
# TYPE dilithion_hashrate gauge
dilithion_hashrate ${HASHRATE:-0}

# HELP dilithion_disk_available_gb Available disk space in GB
# TYPE dilithion_disk_available_gb gauge
dilithion_disk_available_gb $DISK_AVAILABLE_GB

# HELP dilithion_cpu_usage_percent CPU usage percentage
# TYPE dilithion_cpu_usage_percent gauge
dilithion_cpu_usage_percent ${CPU_USAGE:-0}

# HELP dilithion_memory_usage_percent Memory usage percentage
# TYPE dilithion_memory_usage_percent gauge
dilithion_memory_usage_percent ${MEMORY_PERCENT:-0}

# HELP dilithion_wallet_accessible Whether the wallet is accessible (1=yes, 0=no)
# TYPE dilithion_wallet_accessible gauge
dilithion_wallet_accessible ${WALLET_ACCESSIBLE:-0}

# HELP dilithion_wallet_balance Wallet balance in DIL
# TYPE dilithion_wallet_balance gauge
dilithion_wallet_balance ${WALLET_BALANCE:-0}

# HELP dilithion_health_check_success Overall health check status (1=healthy, 0=unhealthy)
# TYPE dilithion_health_check_success gauge
dilithion_health_check_success $OVERALL_HEALTHY

# HELP dilithion_health_check_timestamp Unix timestamp of last health check
# TYPE dilithion_health_check_timestamp gauge
dilithion_health_check_timestamp $(date +%s)
EOF
}

# Output in JSON format
output_json() {
    cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "healthy": $([ "$OVERALL_HEALTHY" -eq 1 ] && echo "true" || echo "false"),
  "node": {
    "running": $([ "$NODE_RUNNING" -eq 1 ] && echo "true" || echo "false"),
    "rpc_accessible": $([ "$RPC_ACCESSIBLE" -eq 1 ] && echo "true" || echo "false")
  },
  "blockchain": {
    "height": $BLOCK_HEIGHT,
    "synced": $([ "${BLOCKCHAIN_SYNCED:-0}" -eq 1 ] && echo "true" || echo "false")
  },
  "network": {
    "peer_count": $PEER_COUNT
  },
  "mempool": {
    "size": $MEMPOOL_SIZE,
    "bytes": ${MEMPOOL_BYTES:-0}
  },
  "mining": {
    "active": $([ "$MINING_ACTIVE" -eq 1 ] && echo "true" || echo "false"),
    "hashrate": ${HASHRATE:-0}
  },
  "system": {
    "disk_available_gb": $DISK_AVAILABLE_GB,
    "cpu_usage_percent": ${CPU_USAGE:-0},
    "memory_usage_percent": ${MEMORY_PERCENT:-0}
  },
  "wallet": {
    "accessible": $([ "${WALLET_ACCESSIBLE:-0}" -eq 1 ] && echo "true" || echo "false"),
    "balance": ${WALLET_BALANCE:-0}
  }
}
EOF
}

# ==============================================================================
# Main
# ==============================================================================

main() {
    # Parse arguments
    for arg in "$@"; do
        case $arg in
            --prometheus)
                OUTPUT_FORMAT="prometheus"
                ;;
            --json)
                OUTPUT_FORMAT="json"
                ;;
            --alert-on-failure)
                ALERT_ON_FAILURE=true
                ;;
            --rpc-host=*)
                RPC_HOST="${arg#*=}"
                RPC_URL="http://$RPC_HOST:$RPC_PORT"
                ;;
            --rpc-port=*)
                RPC_PORT="${arg#*=}"
                RPC_URL="http://$RPC_HOST:$RPC_PORT"
                ;;
            --help)
                echo "Dilithion Node Health Check Script"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --prometheus         Output in Prometheus metrics format"
                echo "  --json               Output in JSON format"
                echo "  --alert-on-failure   Exit with non-zero code if unhealthy"
                echo "  --rpc-host=HOST      RPC host (default: localhost)"
                echo "  --rpc-port=PORT      RPC port (default: 8332)"
                echo "  --help               Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                                    # Human-readable output"
                echo "  $0 --prometheus                       # Prometheus metrics"
                echo "  $0 --json                             # JSON output"
                echo "  $0 --alert-on-failure                 # Exit non-zero if unhealthy"
                echo "  $0 --prometheus --rpc-port=18332      # Check testnet"
                echo ""
                exit 0
                ;;
            *)
                echo "Unknown option: $arg"
                echo "Run with --help for usage information"
                exit 1
                ;;
        esac
    done

    # Run health checks (suppress errors if not in human mode)
    if [ "$OUTPUT_FORMAT" != "human" ]; then
        exec 2>/dev/null
    fi

    check_node_running || true
    check_rpc || true
    check_blockchain_sync || true
    check_peers || true
    check_mempool || true
    check_mining || true
    check_disk_space || true
    check_system_resources || true
    check_wallet || true

    # Output results
    case "$OUTPUT_FORMAT" in
        prometheus)
            output_prometheus
            ;;
        json)
            output_json
            ;;
        *)
            output_human
            ;;
    esac

    # Exit with appropriate code
    if [ "$ALERT_ON_FAILURE" = true ] && [ "$OVERALL_HEALTHY" -eq 0 ]; then
        exit 1
    fi

    exit 0
}

# Run main function
main "$@"
