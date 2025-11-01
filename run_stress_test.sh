#!/bin/bash
set -e
echo "=== 3-Node Stress Test ==="
echo "Start: Tue Oct 28 19:45:22 ACDT 2025"

# Cleanup
rm -rf /tmp/dil_n{1,2,3}
mkdir -p /tmp/dil_n{1,2,3}
pkill -9 dilithion-node 2>/dev/null || true
sleep 2

# Start nodes
echo "Starting nodes..."
nohup ./dilithion-node --datadir=/tmp/dil_n1 --port=8444 --rpcport=8445 --mine --threads=2 >/tmp/n1.log 2>&1 &
sleep 10
nohup ./dilithion-node --datadir=/tmp/dil_n2 --port=9444 --rpcport=9445 --mine --threads=2 --addnode=127.0.0.1:8444 >/tmp/n2.log 2>&1 &
sleep 10
nohup ./dilithion-node --datadir=/tmp/dil_n3 --port=10444 --rpcport=10445 --mine --threads=2 --addnode=127.0.0.1:8444 >/tmp/n3.log 2>&1 &
sleep 10

echo "Monitoring for 15 minutes..."
END=1761643822
while [ 1761642922 -lt  ]; do
    ELAPSED=1761643822
    echo "=== s / 900s ==="
    for P in 8445 9445 10445; do
        H=
        echo "  Port : Height="
    done
    echo ""
    sleep 60
done

echo "=== Complete ===" 
pkill -9 dilithion-node 2>/dev/null || true
