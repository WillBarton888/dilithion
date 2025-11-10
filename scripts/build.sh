#!/bin/bash
################################################################################
# Dilithion Build Script
#
# Builds the Dilithion project with proper environment setup.
# Fixes Windows temp directory permission issues by using /c/tmp instead of
# C:\WINDOWS\.
#
# Usage:
#   ./scripts/build.sh [target]
#
# Examples:
#   ./scripts/build.sh              # Build all (default)
#   ./scripts/build.sh clean        # Clean build artifacts
#   ./scripts/build.sh test         # Build and run tests
#
# Author: Dilithion Core Development Team
# Date: 2025-11-11
################################################################################

set -e  # Exit on error

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Setup environment
setup_environment() {
    log_info "Setting up build environment..."

    # Create user-writable temp directory (fixes Windows permission issues)
    mkdir -p /c/tmp
    log_info "  Temp directory: /c/tmp"

    # Export temp directories (prevents compiler from using C:\WINDOWS\)
    export TMP=/c/tmp
    export TEMP=/c/tmp
    export TMPDIR=/c/tmp
    log_info "  TMP=/c/tmp TEMP=/c/tmp TMPDIR=/c/tmp"

    # Setup PATH for MSYS2/MinGW (Windows)
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        export PATH="/c/msys64/mingw64/bin:/c/msys64/usr/bin:$PATH"
        log_info "  PATH includes MSYS2/MinGW binaries"
    fi

    # Detect number of CPU cores for parallel build
    if command -v nproc &> /dev/null; then
        export MAKEFLAGS="-j$(nproc)"
        log_info "  Parallel build: -j$(nproc)"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        export MAKEFLAGS="-j$(sysctl -n hw.ncpu)"
        log_info "  Parallel build: -j$(sysctl -n hw.ncpu)"
    else
        export MAKEFLAGS="-j4"
        log_info "  Parallel build: -j4 (default)"
    fi
}

# Build function
build() {
    local target="${1:-all}"

    log_info "Building target: $target"

    cd "$PROJECT_ROOT"

    if make "$target" 2>&1 | tee build.log; then
        log_success "Build completed successfully!"
        return 0
    else
        log_error "Build failed! Check build.log for details."
        return 1
    fi
}

# Main
main() {
    local target="${1:-all}"

    echo ""
    echo "================================================================================"
    echo "  Dilithion Build Script"
    echo "================================================================================"
    echo ""

    setup_environment

    if build "$target"; then
        echo ""
        log_success "✓ Build successful"
        echo ""
        return 0
    else
        echo ""
        log_error "✗ Build failed"
        echo ""
        return 1
    fi
}

main "$@"
