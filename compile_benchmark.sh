#!/bin/bash
# Compile Dilithium3 benchmark
set -e

echo "Compiling Dilithium3 Performance Benchmark..."

DILITHIUM_DIR="depends/dilithium/ref"
DILITHIUM_OBJS="$DILITHIUM_DIR/*.o"

# Check for g++
if ! command -v g++ &> /dev/null; then
    echo "ERROR: g++ compiler not found"
    echo "Please install MinGW or GCC for Windows"
    exit 1
fi

# Compile benchmark
g++ -O3 -march=native -std=c++17 \
    -I"$DILITHIUM_DIR" \
    -DDILITHIUM_MODE=3 \
    -o dilithium_benchmark \
    dilithium_benchmark.cpp \
    $DILITHIUM_OBJS \
    -static-libgcc -static-libstdc++

echo "✓ Compilation successful!"
echo "Run with: ./dilithium_benchmark"
echo "For 1-hour stress test: ./dilithium_benchmark --full-stress"
