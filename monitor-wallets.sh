#!/bin/bash
# Monitor wallet balances for 3-node testnet

echo "========================================="
echo "3-Node Testnet Wallet Monitor"
echo "========================================="
echo ""

while true; do
    clear
    echo "========================================="
    echo "Dilithion Testnet - Wallet Balances"
    echo "Time: $(date '+%H:%M:%S')"
    echo "========================================="
    echo ""

    # Node 1
    if [ -f ".dilithion-testnet/wallet.dat" ]; then
        echo "NODE 1 (Port 18444):"
        echo "  Datadir: .dilithion-testnet"
        # Could query RPC here if implemented
        echo "  Status: Mining"
        echo ""
    fi

    # Node 2
    if [ -f ".dilithion-testnet-node2/wallet.dat" ]; then
        echo "NODE 2 (Port 18445):"
        echo "  Datadir: .dilithion-testnet-node2"
        echo "  Status: Mining"
        echo ""
    fi

    # Node 3
    if [ -f ".dilithion-testnet-node3/wallet.dat" ]; then
        echo "NODE 3 (Port 18446):"
        echo "  Datadir: .dilithion-testnet-node3"
        echo "  Status: Mining"
        echo ""
    fi

    echo "========================================="
    echo "Checking block counts..."
    echo ""

    if [ -d ".dilithion-testnet/blocks" ]; then
        count1=$(ls -1 .dilithion-testnet/blocks/*.ldb 2>/dev/null | wc -l)
        echo "Node 1 block files: $count1"
    fi

    if [ -d ".dilithion-testnet-node2/blocks" ]; then
        count2=$(ls -1 .dilithion-testnet-node2/blocks/*.ldb 2>/dev/null | wc -l)
        echo "Node 2 block files: $count2"
    fi

    if [ -d ".dilithion-testnet-node3/blocks" ]; then
        count3=$(ls -1 .dilithion-testnet-node3/blocks/*.ldb 2>/dev/null | wc -l)
        echo "Node 3 block files: $count3"
    fi

    echo ""
    echo "Press Ctrl+C to stop monitoring"
    sleep 5
done
