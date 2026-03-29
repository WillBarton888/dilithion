#!/bin/bash
# Build Dilithium3 WASM module from pqcrystals reference implementation
# Produces dilithium.js + dilithium.wasm in website/js/
#
# This compiles the SAME Dilithium source code the node uses (depends/dilithium/ref/),
# ensuring cryptographic compatibility between node and browser wallets.
#
# Prerequisites:
#   - Emscripten SDK (emsdk) installed and activated
#   - Windows: C:/Users/will/emsdk/emsdk_env.bat
#
# Emscripten version: 3.1.51

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DILITHIUM_REF_DIR="$SCRIPT_DIR/../../depends/dilithium/ref"
OUTPUT_DIR="$SCRIPT_DIR/../js"
WASM_RANDOMBYTES="$SCRIPT_DIR/randombytes_wasm.c"

echo "=== Building Dilithium3 WASM Module (Reference Implementation) ==="
echo "Emscripten: $(emcc --version 2>&1 | head -1)"
echo "Source: $DILITHIUM_REF_DIR"
echo ""

# Verify source files exist
for f in sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c \
         fips202.c symmetric-shake.c; do
    if [ ! -f "$DILITHIUM_REF_DIR/$f" ]; then
        echo "ERROR: Missing source file: $DILITHIUM_REF_DIR/$f"
        exit 1
    fi
done

if [ ! -f "$WASM_RANDOMBYTES" ]; then
    echo "ERROR: Missing WASM randombytes: $WASM_RANDOMBYTES"
    exit 1
fi

# Source files: ref implementation + WASM randombytes (NOT the original randombytes.c)
SOURCES="
    $SCRIPT_DIR/dilithium_wasm.c
    $DILITHIUM_REF_DIR/sign.c
    $DILITHIUM_REF_DIR/packing.c
    $DILITHIUM_REF_DIR/polyvec.c
    $DILITHIUM_REF_DIR/poly.c
    $DILITHIUM_REF_DIR/ntt.c
    $DILITHIUM_REF_DIR/reduce.c
    $DILITHIUM_REF_DIR/rounding.c
    $DILITHIUM_REF_DIR/fips202.c
    $DILITHIUM_REF_DIR/symmetric-shake.c
    $WASM_RANDOMBYTES
"

# Exported functions (JS-accessible API)
EXPORTED_FUNCTIONS='["_dilithium_init","_dilithium_cleanup","_dilithium_get_publickey_bytes","_dilithium_get_secretkey_bytes","_dilithium_get_signature_bytes","_dilithium_get_seed_bytes","_dilithium_keypair","_dilithium3_keypair_seed","_dilithium_sign","_dilithium_verify","_dilithium_malloc","_dilithium_free","_dilithium_secure_free"]'

EXPORTED_RUNTIME_METHODS='["ccall","cwrap","setValue","getValue","HEAPU8","HEAPU32"]'

echo "Compiling..."

emcc -O2 \
    -DDILITHIUM_MODE=3 \
    -DDILITHIUM_RANDOMIZED_SIGNING \
    -I"$DILITHIUM_REF_DIR" \
    -s WASM=1 \
    -s MODULARIZE=1 \
    -s EXPORT_NAME="DilithiumModule" \
    -s INITIAL_MEMORY=2097152 \
    -s STACK_SIZE=1048576 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS" \
    -s EXPORTED_RUNTIME_METHODS="$EXPORTED_RUNTIME_METHODS" \
    -s NO_EXIT_RUNTIME=1 \
    -s FILESYSTEM=0 \
    --no-entry \
    $SOURCES \
    -o "$OUTPUT_DIR/dilithium.js"

echo ""
echo "=== Build Complete ==="
ls -lh "$OUTPUT_DIR/dilithium.js" "$OUTPUT_DIR/dilithium.wasm"
echo ""

# SHA-256 for reproducibility
if command -v sha256sum &> /dev/null; then
    echo "WASM SHA-256: $(sha256sum "$OUTPUT_DIR/dilithium.wasm" | cut -d' ' -f1)"
fi
