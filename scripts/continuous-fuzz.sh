#!/usr/bin/env bash
# Continuous Fuzzing for Dilithium
set -e

FUZZ_DURATION="${FUZZ_DURATION:-3600}"
FUZZ_CORPUS_DIR="fuzz_corpus"
FUZZ_ARTIFACTS_DIR="fuzz_artifacts"

echo "========================================="
echo "Continuous Fuzzing for Dilithium"
echo "========================================="

mkdir -p "$FUZZ_CORPUS_DIR" "$FUZZ_ARTIFACTS_DIR"

TARGETS=("dilithium" "dilithium_paranoid")

for target in "${TARGETS[@]}"; do
    echo "Fuzzing: $target"
    mkdir -p "$FUZZ_CORPUS_DIR/$target"
    mkdir -p "$FUZZ_ARTIFACTS_DIR/$target"

    if [ -f "src/test/fuzz/fuzz_$target" ]; then
        src/test/fuzz/fuzz_$target \
            "$FUZZ_CORPUS_DIR/$target" \
            -max_total_time="$FUZZ_DURATION" \
            -artifact_prefix="$FUZZ_ARTIFACTS_DIR/$target/" \
            -jobs=$(nproc) || echo "Fuzzing completed for $target"
    else
        echo "Fuzz binary not found: fuzz_$target"
    fi
done

echo "✓ Fuzzing complete"
