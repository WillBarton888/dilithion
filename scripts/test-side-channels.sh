#!/usr/bin/env bash
# Side-Channel Resistance Testing for Dilithium
set -e

echo "========================================="
echo "Side-Channel Resistance Testing"
echo "========================================="

# Check for test binary
if [ ! -f "src/test/test_bitcoin" ]; then
    echo "ERROR: test_bitcoin not found. Build tests first."
    exit 1
fi

echo "[1/3] Cache Timing Analysis..."
valgrind --tool=cachegrind \
         --cachegrind-out-file=cachegrind.out \
         ./src/test/test_bitcoin \
         --run_test=dilithium_tests/dilithium_sign_verify_basic

echo "[2/3] Memory Access Pattern Analysis..."
valgrind --tool=memcheck \
         --leak-check=full \
         --log-file=memcheck.out \
         ./src/test/test_bitcoin \
         --run_test=dilithium_tests

echo "[3/3] Timing Variance Analysis..."
for i in {1..100}; do
    /usr/bin/time -f "%e" ./src/test/test_bitcoin \
        --run_test=dilithium_tests/dilithium_sign_verify_basic \
        2>&1 | grep -E '^[0-9]+\.[0-9]+$' >> timing_test.log
done

echo "✓ Side-channel testing complete"
echo "Review cachegrind.out, memcheck.out, and timing_test.log"
