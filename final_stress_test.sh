#!/bin/bash
# 15-minute 3-node stress test
echo "=== Dilithion 3-Node Stress Test ===" 
echo "Start: Tue Oct 28 19:53:50 ACDT 2025"

# Cleanup
rm -rf /tmp/dil_{1,2,3}
mkdir -p /tmp/dil_{1,2,3}
pkill -9 dilithion-node 2>/dev/null || true
sleep 2

# Start nodes in background
nohup ./dilithion-node --datadir=/tmp/dil_1 --port=8444 --rpcport=8445 --mine --threads=2 >/tmp/log1.txt 2>&1 &
sleep 10
nohup ./dilithion-node --datadir=/tmp/dil_2 --port=9444 --rpcport=9445 --mine --threads=2 --addnode=127.0.0.1:8444 >/tmp/log2.txt 2>&1 &
sleep 10  
nohup ./dilithion-node --datadir=/tmp/dil_3 --port=10444 --rpcport=10445 --mine --threads=2 --addnode=127.0.0.1:8444 >/tmp/log3.txt 2>&1 &
sleep 10

echo "Nodes started. Monitoring for 15 minutes..."
END_TIME=1761644330

while [ 1761643430 -lt  ]; do
    ELAPSED=1761644330
    echo "=== s / 900s ==="
    
    for P in 8445 9445 10445; do
        INFO=
        HEIGHT=
        PEERS=
        echo "  Port : Height= Peers="
    done
    echo ""
    sleep 60
done

echo "=== Test Complete ==="
pkill -9 dilithion-node 2>/dev/null || true
