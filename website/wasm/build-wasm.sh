#!/bin/bash
# Build Dilithium WASM module with proper memory settings
# Run from msys2/mingw64 environment with Emscripten activated

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBOQS_DIR="../../depends/liboqs"
OUTPUT_DIR="../js"

# Check if liboqs exists
if [ ! -d "$LIBOQS_DIR/build" ]; then
    echo "Error: liboqs build not found at $LIBOQS_DIR/build"
    echo "Please build liboqs for Emscripten first"
    exit 1
fi

echo "=== Building Dilithium WASM Module ==="

# Emscripten compile flags
# - INITIAL_MEMORY: 256MB (enough for Dilithium operations)
# - STACK_SIZE: 8MB (Dilithium uses lots of stack space)
# - ALLOW_MEMORY_GROWTH: let memory grow if needed
# - MODULARIZE: create a module factory function
# - EXPORT_ES6=0: use CommonJS/UMD style
# - EXPORTED_FUNCTIONS: our C API functions
# - EXPORTED_RUNTIME_METHODS: helpers for JS interop

EXPORTED_FUNCTIONS='["_dilithium_init","_dilithium_cleanup","_dilithium_get_publickey_bytes","_dilithium_get_secretkey_bytes","_dilithium_get_signature_bytes","_dilithium_keypair","_dilithium_sign","_dilithium_verify","_dilithium_malloc","_dilithium_free"]'

EXPORTED_RUNTIME_METHODS='["ccall","cwrap","setValue","getValue","HEAPU8","HEAPU32"]'

echo "Compiling dilithium_wasm.c..."

emcc -O2 \
    -I"$LIBOQS_DIR/build/include" \
    -L"$LIBOQS_DIR/build/lib" \
    -s WASM=1 \
    -s MODULARIZE=1 \
    -s EXPORT_NAME="DilithiumModule" \
    -s INITIAL_MEMORY=268435456 \
    -s STACK_SIZE=8388608 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS" \
    -s EXPORTED_RUNTIME_METHODS="$EXPORTED_RUNTIME_METHODS" \
    -s NO_EXIT_RUNTIME=1 \
    -loqs \
    dilithium_wasm.c \
    -o "$OUTPUT_DIR/dilithium.js"

echo ""
echo "=== Build Complete ==="
echo "Output files:"
ls -la "$OUTPUT_DIR/dilithium.js" "$OUTPUT_DIR/dilithium.wasm"
echo ""
echo "WASM file size: $(du -h "$OUTPUT_DIR/dilithium.wasm" | cut -f1)"
