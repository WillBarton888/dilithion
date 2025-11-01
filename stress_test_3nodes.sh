#!/bin/bash
# Dilithion 3-Node Stress Test
# Duration: 15 minutes
# Purpose: Test network stability, peer connections, and block propagation

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Dilithion 3-Node Stress Test ===${NC}"
echo "Test duration: 15 minutes"
echo "Start time: $(date)"
echo ""

# Clean up any existing test data
echo -e "${YELLOW}Cleaning up previous test data...${NC}"
rm -rf /tmp/dilithion_node1 /tmp/dilithion_node2 /tmp/dilithion_node3
mkdir -p /tmp/dilithion_node1 /tmp/dilithion_node2 /tmp/dilithion_node3

# Kill any existing dilithion-node processes
pkill -9 dilithion-node 2>/dev/null || true
sleep 2

# Start Node 1 (Seed Node) - Port 8444
echo -e "${GREEN}Starting Node 1 (Seed) - Port 8444, RPC 8445${NC}"
./dilithion-node \
  --datadir=/tmp/dilithion_node1 \
  --port=8444 \
  --rpcport=8445 \
  --mine \
  --threads=4 \
  > /tmp/node1.log 2>&1 &
NODE1_PID=$!
echo "Node 1 PID: $NODE1_PID"
sleep 5

# Start Node 2 - Port 9444, connects to Node 1
echo -e "${GREEN}Starting Node 2 - Port 9444, RPC 9445${NC}"
./dilithion-node \
  --datadir=/tmp/dilithion_node2 \
  --port=9444 \
  --rpcport=9445 \
  --mine \
  --threads=4 \
  --addnode=127.0.0.1:8444 \
  > /tmp/node2.log 2>&1 &
NODE2_PID=$!
echo "Node 2 PID: $NODE2_PID"
sleep 5

# Start Node 3 - Port 10444, connects to Node 1
echo -e "${GREEN}Starting Node 3 - Port 10444, RPC 10445${NC}"
./dilithion-node \
  --datadir=/tmp/dilithion_node3 \
  --port=10444 \
  --rpcport=10445 \
  --mine \
  --threads=4 \
  --addnode=127.0.0.1:8444 \
  > /tmp/node3.log 2>&1 &
NODE3_PID=$!
echo "Node 3 PID: $NODE3_PID"
sleep 5

echo ""
echo -e "${GREEN}All 3 nodes started!${NC}"
echo "Node 1: PID $NODE1_PID (Port 8444, RPC 8445)"
echo "Node 2: PID $NODE2_PID (Port 9444, RPC 9445)"
echo "Node 3: PID $NODE3_PID (Port 10444, RPC 10445)"
echo ""

# Create monitoring script
cat > /tmp/monitor.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring Started: $(date) ==="
echo ""

# Function to query RPC
query_node() {
    local port=$1
    local method=$2
    curl -s http://localhost:$port \
      -X POST \
      -H "Content-Type: application/json" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" \
      2>/dev/null | grep -o '"result":[^,}]*' | cut -d':' -f2
}

# Monitor for 15 minutes (900 seconds)
end_time=$(($(date +%s) + 900))
interval=60  # Check every 60 seconds

while [ $(date +%s) -lt $end_time ]; do
    elapsed=$(( 900 - (end_time - $(date +%s)) ))
    remaining=$(( end_time - $(date +%s) ))

    echo "=== Status Update - Elapsed: ${elapsed}s / Remaining: ${remaining}s ==="
    echo "Time: $(date '+%H:%M:%S')"
    echo ""

    # Node 1
    echo "Node 1 (Port 8445):"
    height1=$(query_node 8445 getblockcount)
    peers1=$(query_node 8445 getpeerinfo | grep -o '{' | wc -l)
    mining1=$(query_node 8445 getmininginfo)
    echo "  Block Height: $height1"
    echo "  Peer Count: $peers1"
    echo "  Mining: $mining1"

    # Node 2
    echo "Node 2 (Port 9445):"
    height2=$(query_node 9445 getblockcount)
    peers2=$(query_node 9445 getpeerinfo | grep -o '{' | wc -l)
    mining2=$(query_node 9445 getmininginfo)
    echo "  Block Height: $height2"
    echo "  Peer Count: $peers2"
    echo "  Mining: $mining2"

    # Node 3
    echo "Node 3 (Port 10445):"
    height3=$(query_node 10445 getblockcount)
    peers3=$(query_node 10445 getpeerinfo | grep -o '{' | wc -l)
    mining3=$(query_node 10445 getmininginfo)
    echo "  Block Height: $height3"
    echo "  Peer Count: $peers3"
    echo "  Mining: $mining3"

    echo ""
    echo "Summary: Blocks [N1:$height1, N2:$height2, N3:$height3] | Peers [N1:$peers1, N2:$peers2, N3:$peers3]"
    echo "----------------------------------------"
    echo ""

    sleep $interval
done

echo ""
echo "=== Monitoring Complete: $(date) ==="
EOF

chmod +x /tmp/monitor.sh

# Start monitoring in background
echo -e "${YELLOW}Starting 15-minute monitoring...${NC}"
echo ""
/tmp/monitor.sh | tee /tmp/stress_test_results.log &
MONITOR_PID=$!

# Wait for 15 minutes
sleep 900

# Stop monitoring
kill $MONITOR_PID 2>/dev/null || true

# Collect final statistics
echo ""
echo -e "${GREEN}=== Test Complete ===${NC}"
echo "End time: $(date)"
echo ""

# Final status check
echo -e "${YELLOW}Final Status Check:${NC}"
curl -s http://localhost:8445 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}' 2>/dev/null || echo "Node 1 not responding"
echo ""
curl -s http://localhost:9445 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}' 2>/dev/null || echo "Node 2 not responding"
echo ""
curl -s http://localhost:10445 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}' 2>/dev/null || echo "Node 3 not responding"
echo ""

# Check for crashes
echo -e "${YELLOW}Checking for crashes:${NC}"
if ps -p $NODE1_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Node 1 still running${NC}"
else
    echo -e "${RED}✗ Node 1 crashed${NC}"
fi

if ps -p $NODE2_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Node 2 still running${NC}"
else
    echo -e "${RED}✗ Node 2 crashed${NC}"
fi

if ps -p $NODE3_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Node 3 still running${NC}"
else
    echo -e "${RED}✗ Node 3 crashed${NC}"
fi

echo ""
echo -e "${YELLOW}Stopping all nodes...${NC}"
kill $NODE1_PID $NODE2_PID $NODE3_PID 2>/dev/null || true
sleep 2
pkill -9 dilithion-node 2>/dev/null || true

echo ""
echo -e "${GREEN}Stress test complete!${NC}"
echo "Results saved to: /tmp/stress_test_results.log"
echo "Node logs available at:"
echo "  - /tmp/node1.log"
echo "  - /tmp/node2.log"
echo "  - /tmp/node3.log"
