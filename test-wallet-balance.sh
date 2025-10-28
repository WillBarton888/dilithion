#!/bin/bash
# Test Script: Wallet Balance Crediting
#
# This script tests that mined blocks properly credit the wallet balance
# by running a single mining node and displaying wallet balance updates.
#
# Usage: ./test-wallet-balance.sh

echo "========================================="
echo "Dilithion Wallet Balance Test"
echo "========================================="
echo ""
echo "This test will:"
echo "1. Clean up any existing testnet data"
echo "2. Start a single mining node"
echo "3. Mine blocks for 60 seconds"
echo "4. Display wallet balance updates in real-time"
echo ""
echo "Expected behavior:"
echo "- Each mined block should credit 50.00000000 DIL"
echo "- Balance should accumulate (50, 100, 150, etc.)"
echo "- You should see '[Wallet] Coinbase credited:' messages"
echo "- You should see '[Wallet] Total Balance:' updates"
echo ""
echo "========================================="
echo ""

# Kill any running nodes
echo "Cleaning up..."
pkill -9 dilithion-node 2>/dev/null
sleep 2

# Clean testnet data
rm -rf .dilithion-testnet
mkdir -p .dilithion-testnet/blocks
echo "✓ Cleaned testnet data"
echo ""

# Start the test
echo "========================================="
echo "Starting mining node (60 seconds)..."
echo "========================================="
echo ""

timeout 60 ./dilithion-node --testnet --mine --threads=2

echo ""
echo "========================================="
echo "Test Complete!"
echo "========================================="
echo ""
echo "Review the output above to verify:"
echo "1. Blocks were found (look for '✓ BLOCK FOUND!' messages)"
echo "2. Coinbase transactions were credited (look for '[Wallet] Coinbase credited:' messages)"
echo "3. Balance accumulated correctly (look for '[Wallet] Total Balance:' updates)"
echo ""
echo "If you see the expected behavior, the wallet balance feature is working correctly!"
echo ""
