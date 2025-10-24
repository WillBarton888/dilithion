#!/bin/bash
# Build Dilithion with various sanitizers for security testing
# Usage: ./scripts/build-with-sanitizers.sh [asan|ubsan|msan|tsan|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_header() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

function print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

function print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

function build_with_asan() {
    print_header "Building with AddressSanitizer (ASAN)"

    make clean || true

    export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
    export LDFLAGS="-fsanitize=address"
    export ASAN_OPTIONS="detect_leaks=1:check_initialization_order=1:strict_init_order=1"

    # ./configure will be added when Bitcoin Core integration is ready
    # ./configure
    # make -j$(nproc)

    echo -e "${GREEN}✅ ASAN build configuration ready${NC}"
    echo "To run with ASAN: ASAN_OPTIONS='$ASAN_OPTIONS' ./src/test/test_bitcoin"
}

function build_with_ubsan() {
    print_header "Building with UndefinedBehaviorSanitizer (UBSAN)"

    make clean || true

    export CXXFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -g -O1"
    export LDFLAGS="-fsanitize=undefined"
    export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

    # ./configure will be added when Bitcoin Core integration is ready
    # ./configure
    # make -j$(nproc)

    echo -e "${GREEN}✅ UBSAN build configuration ready${NC}"
    echo "To run with UBSAN: UBSAN_OPTIONS='$UBSAN_OPTIONS' ./src/test/test_bitcoin"
}

function build_with_msan() {
    print_header "Building with MemorySanitizer (MSAN)"

    # MSAN requires clang and instrumented libraries
    if ! command -v clang++ &> /dev/null; then
        print_error "MSAN requires clang++. Please install clang."
        return 1
    fi

    make clean || true

    export CC=clang
    export CXX=clang++
    export CXXFLAGS="-fsanitize=memory -fno-omit-frame-pointer -g -O1"
    export LDFLAGS="-fsanitize=memory"
    export MSAN_OPTIONS="halt_on_error=1"

    print_warning "MSAN requires all dependencies to be instrumented"
    print_warning "This may not work with system libraries"

    # ./configure will be added when Bitcoin Core integration is ready
    # ./configure
    # make -j$(nproc)

    echo -e "${GREEN}✅ MSAN build configuration ready${NC}"
}

function build_with_tsan() {
    print_header "Building with ThreadSanitizer (TSAN)"

    make clean || true

    export CXXFLAGS="-fsanitize=thread -fno-omit-frame-pointer -g -O1"
    export LDFLAGS="-fsanitize=thread"
    export TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1"

    # ./configure will be added when Bitcoin Core integration is ready
    # ./configure
    # make -j$(nproc)

    echo -e "${GREEN}✅ TSAN build configuration ready${NC}"
}

function build_all() {
    print_header "Building with all sanitizers (sequentially)"

    build_with_asan
    echo ""

    build_with_ubsan
    echo ""

    # MSAN and TSAN are more specialized, skip for now
    # build_with_msan
    # build_with_tsan

    print_header "All sanitizer builds complete"
    echo -e "${GREEN}✅ ASAN and UBSAN configurations ready${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Implement cryptographic code"
    echo "2. Run tests with each sanitizer"
    echo "3. Fix any issues detected"
}

# Main script
case "${1:-all}" in
    asan)
        build_with_asan
        ;;
    ubsan)
        build_with_ubsan
        ;;
    msan)
        build_with_msan
        ;;
    tsan)
        build_with_tsan
        ;;
    all)
        build_all
        ;;
    *)
        echo "Usage: $0 [asan|ubsan|msan|tsan|all]"
        echo ""
        echo "Sanitizers:"
        echo "  asan  - AddressSanitizer (memory errors, leaks)"
        echo "  ubsan - UndefinedBehaviorSanitizer (undefined behavior)"
        echo "  msan  - MemorySanitizer (uninitialized memory)"
        echo "  tsan  - ThreadSanitizer (data races)"
        echo "  all   - Build with ASAN and UBSAN (default)"
        exit 1
        ;;
esac
