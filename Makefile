# Dilithion Cryptocurrency Makefile
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

# ============================================================================
# Configuration
# ============================================================================

# Detect operating system
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

# Compiler and flags
CXX := g++
# Use ?= to allow environment variables (e.g., --coverage) to completely override defaults
# If not set by environment, use optimized defaults
# Note: -pipe avoids temp file issues on Windows
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -pipe
CFLAGS ?= -O2

# Include paths (base)
INCLUDES := -I src \
            -I depends/randomx/src \
            -I depends/dilithium/ref

# Library paths and libraries (base)
# Use ?= to allow environment to set initial LDFLAGS (e.g., --coverage)
# Then append our library paths
LDFLAGS ?=

# Platform-specific RandomX build directory
ifeq ($(UNAME_S),Windows)
    RANDOMX_BUILD_DIR := depends/randomx/build-windows
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    RANDOMX_BUILD_DIR := depends/randomx/build-windows
else ifneq (,$(findstring MSYS,$(UNAME_S)))
    RANDOMX_BUILD_DIR := depends/randomx/build-windows
else
    # Linux, macOS, and other Unix-like systems
    RANDOMX_BUILD_DIR := depends/randomx/build
endif

LDFLAGS += -L $(RANDOMX_BUILD_DIR) \
           -L depends/dilithium/ref

# FIX-007 (CRYPT-001/006): Add OpenSSL for secure AES-256 implementation
LIBS := -lrandomx -lleveldb -lpthread -lssl -lcrypto

# Platform-specific configuration
ifeq ($(UNAME_S),Darwin)
    # macOS with Homebrew
    HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
    INCLUDES += -I$(HOMEBREW_PREFIX)/opt/leveldb/include
    LDFLAGS += -L$(HOMEBREW_PREFIX)/opt/leveldb/lib
else ifeq ($(UNAME_S),Windows)
    # Windows requires ws2_32 for sockets and bcrypt for secure RNG
    LIBS += -lws2_32 -lbcrypt
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    # MinGW/MSYS2 on Windows
    LIBS += -lws2_32 -lbcrypt
else ifneq (,$(findstring MSYS,$(UNAME_S)))
    # MSYS on Windows
    LIBS += -lws2_32 -lbcrypt
endif

# Fix for Windows: Set temp directories to avoid C:\WINDOWS\ permission issues
# This must be set BEFORE any compilation happens
ifeq ($(UNAME_S),Windows)
    export TMP := /c/tmp
    export TEMP := /c/tmp
    export TMPDIR := /c/tmp
    $(shell mkdir -p /c/tmp 2>/dev/null)
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    export TMP := /c/tmp
    export TEMP := /c/tmp
    export TMPDIR := /c/tmp
    $(shell mkdir -p /c/tmp 2>/dev/null)
else ifneq (,$(findstring MSYS,$(UNAME_S)))
    export TMP := /c/tmp
    export TEMP := /c/tmp
    export TMPDIR := /c/tmp
    $(shell mkdir -p /c/tmp 2>/dev/null)
endif

# Dilithium C files (compiled separately)
DILITHIUM_DIR := depends/dilithium/ref
DILITHIUM_SOURCES := $(DILITHIUM_DIR)/sign.c \
                     $(DILITHIUM_DIR)/packing.c \
                     $(DILITHIUM_DIR)/polyvec.c \
                     $(DILITHIUM_DIR)/poly.c \
                     $(DILITHIUM_DIR)/ntt.c \
                     $(DILITHIUM_DIR)/reduce.c \
                     $(DILITHIUM_DIR)/rounding.c \
                     $(DILITHIUM_DIR)/symmetric-shake.c \
                     $(DILITHIUM_DIR)/fips202.c \
                     $(DILITHIUM_DIR)/randombytes.c
DILITHIUM_OBJECTS := $(DILITHIUM_SOURCES:.c=.o)

# Build directory
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj

# Colors for output
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_BLUE := \033[34m
COLOR_YELLOW := \033[33m

# ============================================================================
# Source Files
# ============================================================================

# Core source files (organized by module)
CONSENSUS_SOURCES := src/consensus/fees.cpp \
                     src/consensus/pow.cpp \
                     src/consensus/chain.cpp \
                     src/consensus/tx_validation.cpp \
                     src/consensus/validation.cpp

CORE_SOURCES_UTIL := src/core/chainparams.cpp

CRYPTO_SOURCES := src/crypto/randomx_hash.cpp \
                  src/crypto/sha3.cpp \
                  src/crypto/hmac_sha3.cpp \
                  src/crypto/pbkdf2_sha3.cpp

MINER_SOURCES := src/miner/controller.cpp

NET_SOURCES := src/net/protocol.cpp \
               src/net/serialize.cpp \
               src/net/net.cpp \
               src/net/peers.cpp \
               src/net/socket.cpp \
               src/net/dns.cpp \
               src/net/tx_relay.cpp \
               src/net/async_broadcaster.cpp \
               src/net/headers_manager.cpp \
               src/net/orphan_manager.cpp

NODE_SOURCES := src/node/block_index.cpp \
                src/node/blockchain_storage.cpp \
                src/node/mempool.cpp \
                src/node/genesis.cpp \
                src/node/utxo_set.cpp

PRIMITIVES_SOURCES := src/primitives/block.cpp \
                      src/primitives/transaction.cpp

RPC_SOURCES := src/rpc/server.cpp \
               src/rpc/auth.cpp \
               src/rpc/ratelimiter.cpp \
               src/rpc/permissions.cpp

API_SOURCES := src/api/http_server.cpp

WALLET_SOURCES := src/wallet/wallet.cpp \
                  src/wallet/crypter.cpp \
                  src/wallet/passphrase_validator.cpp \
                  src/wallet/mnemonic.cpp \
                  src/wallet/hd_derivation.cpp \
                  src/wallet/wallet_manager.cpp \
                  src/wallet/wallet_manager_wizard.cpp \
                  src/wallet/wallet_init.cpp \
                  src/wallet/wal.cpp \
                  src/wallet/wal_recovery.cpp

UTIL_SOURCES := src/util/strencodings.cpp \
                src/util/base58.cpp \
                src/util/system.cpp

# Combine all core sources
CORE_SOURCES := $(CONSENSUS_SOURCES) \
                $(CORE_SOURCES_UTIL) \
                $(CRYPTO_SOURCES) \
                $(MINER_SOURCES) \
                $(NET_SOURCES) \
                $(NODE_SOURCES) \
                $(PRIMITIVES_SOURCES) \
                $(RPC_SOURCES) \
                $(API_SOURCES) \
                $(UTIL_SOURCES) \
                $(WALLET_SOURCES)

# Object files
CORE_OBJECTS := $(CORE_SOURCES:src/%.cpp=$(OBJ_DIR)/%.o)

# Main application sources
DILITHION_NODE_SOURCE := src/node/dilithion-node.cpp
GENESIS_GEN_SOURCE := src/test/genesis_test.cpp

# Test sources
PHASE1_TEST_SOURCE := src/test/phase1_simple_test.cpp
MINER_TEST_SOURCE := src/test/miner_tests.cpp
WALLET_TEST_SOURCE := src/test/wallet_tests.cpp
RPC_TEST_SOURCE := src/test/rpc_tests.cpp
RPC_AUTH_TEST_SOURCE := src/test/rpc_auth_tests.cpp
RPC_HD_WALLET_TEST_SOURCE := src/test/rpc_hd_wallet_tests.cpp
TIMESTAMP_TEST_SOURCE := src/test/timestamp_tests.cpp
CRYPTER_TEST_SOURCE := src/test/crypter_tests.cpp
WALLET_ENCRYPTION_INTEGRATION_TEST_SOURCE := src/test/wallet_encryption_integration_tests.cpp
WALLET_PERSISTENCE_TEST_SOURCE := src/test/wallet_persistence_tests.cpp
INTEGRATION_TEST_SOURCE := src/test/integration_tests.cpp
NET_TEST_SOURCE := src/test/net_tests.cpp
TX_VALIDATION_TEST_SOURCE := src/test/tx_validation_tests.cpp
TX_RELAY_TEST_SOURCE := src/test/tx_relay_tests.cpp
MINING_INTEGRATION_TEST_SOURCE := src/test/mining_integration_tests.cpp
PASSPHRASE_VALIDATOR_TEST_SOURCE := test_passphrase_validator.cpp

# Boost Unit Test sources
BOOST_TEST_MAIN_SOURCE := src/test/test_dilithion.cpp
BOOST_CRYPTO_TEST_SOURCE := src/test/crypto_tests.cpp
BOOST_HMAC_SHA3_TEST_SOURCE := src/test/hmac_sha3_tests.cpp
BOOST_PBKDF2_TEST_SOURCE := src/test/pbkdf2_tests.cpp
BOOST_TRANSACTION_TEST_SOURCE := src/test/transaction_tests.cpp
BOOST_BLOCK_TEST_SOURCE := src/test/block_tests.cpp
BOOST_UTIL_TEST_SOURCE := src/test/util_tests.cpp
BOOST_MNEMONIC_TEST_SOURCE := src/test/mnemonic_tests.cpp
BOOST_HD_DERIVATION_TEST_SOURCE := src/test/hd_derivation_tests.cpp
BOOST_WALLET_HD_TEST_SOURCE := src/test/wallet_hd_tests.cpp

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean install help tests test depends
.DEFAULT_GOAL := all

# Default target: build main binaries and utilities
all: dilithion-node genesis_gen check-wallet-balance
	@echo "$(COLOR_GREEN)✓ Build complete!$(COLOR_RESET)"
	@echo "  dilithion-node:        $(shell ls -lh dilithion-node 2>/dev/null | awk '{print $$5}')"
	@echo "  genesis_gen:           $(shell ls -lh genesis_gen 2>/dev/null | awk '{print $$5}')"
	@echo "  check-wallet-balance:  $(shell ls -lh check-wallet-balance 2>/dev/null | awk '{print $$5}')"

# ============================================================================
# Main Binaries
# ============================================================================

dilithion-node: $(CORE_OBJECTS) $(OBJ_DIR)/node/dilithion-node.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ dilithion-node built successfully$(COLOR_RESET)"

genesis_gen: $(CORE_OBJECTS) $(OBJ_DIR)/test/genesis_test.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ genesis_gen built successfully$(COLOR_RESET)"

inspect_db: $(CORE_OBJECTS) $(OBJ_DIR)/tools/inspect_db.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ inspect_db built successfully$(COLOR_RESET)"

check-wallet-balance: $(CORE_OBJECTS) $(OBJ_DIR)/check-wallet-balance.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ check-wallet-balance built successfully$(COLOR_RESET)"

# ============================================================================
# Test Binaries
# ============================================================================

tests: phase1_test miner_tests wallet_tests rpc_tests rpc_auth_tests timestamp_tests crypter_tests wallet_encryption_integration_tests wallet_persistence_tests integration_tests net_tests tx_validation_tests tx_relay_tests mining_integration_tests test_passphrase_validator
	@echo "$(COLOR_GREEN)✓ All tests built successfully$(COLOR_RESET)"

phase1_test: $(CORE_OBJECTS) $(OBJ_DIR)/test/phase1_simple_test.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

miner_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/miner_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

wallet_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/wallet_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

rpc_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/rpc_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

rpc_auth_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/rpc_auth_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

timestamp_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/timestamp_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

crypter_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/crypter_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

wallet_encryption_integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/wallet_encryption_integration_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

wallet_persistence_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/wallet_persistence_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/integration_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

net_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/net_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

tx_validation_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/tx_validation_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

tx_relay_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/tx_relay_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

mining_integration_tests: $(CORE_OBJECTS) $(OBJ_DIR)/test/mining_integration_tests.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

test_passphrase_validator: $(OBJ_DIR)/wallet/passphrase_validator.o $(OBJ_DIR)/test_passphrase_validator.o
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

validate_crypto: validate_crypto.o $(OBJ_DIR)/crypto/hmac_sha3.o $(OBJ_DIR)/crypto/pbkdf2_sha3.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# ============================================================================
# Boost Unit Test Binaries
# ============================================================================

test_dilithion: $(OBJ_DIR)/test/test_dilithion.o $(OBJ_DIR)/test/crypto_tests.o $(OBJ_DIR)/test/hmac_sha3_tests.o $(OBJ_DIR)/test/pbkdf2_tests.o $(OBJ_DIR)/test/transaction_tests.o $(OBJ_DIR)/test/block_tests.o $(OBJ_DIR)/test/util_tests.o $(OBJ_DIR)/test/mnemonic_tests.o $(OBJ_DIR)/test/hd_derivation_tests.o $(OBJ_DIR)/test/wallet_hd_tests.o $(OBJ_DIR)/test/rpc_hd_wallet_tests.o $(OBJ_DIR)/test/difficulty_tests.o $(OBJ_DIR)/test/validation_integration_tests.o $(OBJ_DIR)/test/consensus_validation_tests.o $(OBJ_DIR)/test/utxo_tests.o $(OBJ_DIR)/test/tx_validation_tests.o $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/crypto/randomx_hash.o $(OBJ_DIR)/crypto/hmac_sha3.o $(OBJ_DIR)/crypto/pbkdf2_sha3.o $(OBJ_DIR)/wallet/mnemonic.o $(OBJ_DIR)/wallet/hd_derivation.o $(OBJ_DIR)/wallet/wallet.o $(OBJ_DIR)/wallet/crypter.o $(OBJ_DIR)/wallet/passphrase_validator.o $(OBJ_DIR)/util/base58.o $(OBJ_DIR)/util/strencodings.o $(OBJ_DIR)/primitives/transaction.o $(OBJ_DIR)/primitives/block.o $(OBJ_DIR)/consensus/pow.o $(OBJ_DIR)/consensus/validation.o $(OBJ_DIR)/consensus/fees.o $(OBJ_DIR)/consensus/tx_validation.o $(OBJ_DIR)/core/chainparams.o $(OBJ_DIR)/node/block_index.o $(OBJ_DIR)/node/utxo_set.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ Boost test suite built successfully (header-only)$(COLOR_RESET)"

# ============================================================================
# Difficulty Determinism Test (Week 4 Track B - CRITICAL CONSENSUS TEST)
# ============================================================================

difficulty_determinism_test: $(OBJ_DIR)/test/difficulty_determinism_test.o $(OBJ_DIR)/consensus/pow.o $(OBJ_DIR)/core/chainparams.o $(OBJ_DIR)/primitives/block.o $(OBJ_DIR)/crypto/randomx_hash.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[LINK]$(COLOR_RESET) $@"
	@$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "$(COLOR_GREEN)✓ Difficulty determinism test built successfully$(COLOR_RESET)"

# ============================================================================
# Run Tests
# ============================================================================

test: tests test_dilithion
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Running Boost Unit Test Suite$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@./test_dilithion --log_level=test_suite --report_level=short || true
	@echo ""
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Running Legacy Test Suite$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)========================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 1 tests...$(COLOR_RESET)"
	@./phase1_test
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 3 miner tests...$(COLOR_RESET)"
	@./miner_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 4 wallet tests...$(COLOR_RESET)"
	@timeout 10 ./wallet_tests || true
	@echo ""
	@echo "$(COLOR_YELLOW)Running Phase 4 RPC tests...$(COLOR_RESET)"
	@timeout 10 ./rpc_tests || true
	@echo ""
	@echo "$(COLOR_YELLOW)Running RPC authentication tests...$(COLOR_RESET)"
	@./rpc_auth_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running timestamp validation tests...$(COLOR_RESET)"
	@./timestamp_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running wallet encryption tests...$(COLOR_RESET)"
	@./crypter_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running wallet encryption integration tests...$(COLOR_RESET)"
	@./wallet_encryption_integration_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running wallet persistence tests...$(COLOR_RESET)"
	@./wallet_persistence_tests
	@echo ""
	@echo "$(COLOR_YELLOW)Running passphrase validator tests...$(COLOR_RESET)"
	@./test_passphrase_validator
	@echo ""
	@echo "$(COLOR_YELLOW)Running integration tests...$(COLOR_RESET)"
	@./integration_tests
	@echo ""
	@echo "$(COLOR_GREEN)✓ All test suites complete$(COLOR_RESET)"

# ============================================================================
# Object File Rules
# ============================================================================

# Create build directories
$(OBJ_DIR)/consensus \
$(OBJ_DIR)/core \
$(OBJ_DIR)/crypto \
$(OBJ_DIR)/miner \
$(OBJ_DIR)/net \
$(OBJ_DIR)/node \
$(OBJ_DIR)/primitives \
$(OBJ_DIR)/rpc \
$(OBJ_DIR)/wallet \
$(OBJ_DIR)/util \
$(OBJ_DIR)/api \
$(OBJ_DIR)/test \
$(OBJ_DIR)/test/fuzz:
	@mkdir -p $@

# Compile C++ source files
$(OBJ_DIR)/%.o: src/%.cpp | $(OBJ_DIR)/consensus $(OBJ_DIR)/core $(OBJ_DIR)/crypto $(OBJ_DIR)/miner $(OBJ_DIR)/net $(OBJ_DIR)/node $(OBJ_DIR)/primitives $(OBJ_DIR)/rpc $(OBJ_DIR)/wallet $(OBJ_DIR)/util $(OBJ_DIR)/api $(OBJ_DIR)/test
	@echo "$(COLOR_BLUE)[CXX]$(COLOR_RESET)  $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile utility C++ files from root directory
$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	@echo "$(COLOR_BLUE)[CXX]$(COLOR_RESET)  $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile Dilithium C files
$(DILITHIUM_DIR)/%.o: $(DILITHIUM_DIR)/%.c
	@echo "$(COLOR_BLUE)[CC]$(COLOR_RESET)   $<"
	@gcc $(CFLAGS) -DDILITHIUM_MODE=3 -I $(DILITHIUM_DIR) -c $< -o $@

# Fuzzer harness files (MUST compile with sanitizers for libFuzzer integration)
$(OBJ_DIR)/test/fuzz/%.o: src/test/fuzz/%.cpp | $(OBJ_DIR)/test/fuzz
	@echo "$(COLOR_BLUE)[FUZZ-CXX]$(COLOR_RESET) $<"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -c $< -o $@

# ============================================================================
# Dependencies
# ============================================================================

depends:
	@echo "$(COLOR_YELLOW)Building dependencies...$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)[RandomX]$(COLOR_RESET) Building RandomX library..."
	@cd depends/randomx && mkdir -p build-windows && cd build-windows && cmake -DCMAKE_SYSTEM_PROCESSOR=x86_64 -G "MSYS Makefiles" .. && make
	@echo "$(COLOR_BLUE)[Dilithium]$(COLOR_RESET) Building Dilithium library..."
	@cd depends/dilithium/ref && make
	@echo "$(COLOR_GREEN)✓ Dependencies built$(COLOR_RESET)"

# ============================================================================
# Utility Targets
# ============================================================================

clean:
	@echo "$(COLOR_YELLOW)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -rf $(BUILD_DIR)
	@rm -f dilithion-node genesis_gen
	@rm -f phase1_test miner_tests wallet_tests rpc_tests rpc_auth_tests timestamp_tests crypter_tests wallet_encryption_integration_tests wallet_persistence_tests integration_tests net_tests tx_validation_tests tx_relay_tests mining_integration_tests
	@rm -f test_dilithion
	@rm -f $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)"

install: dilithion-node genesis_gen
	@echo "$(COLOR_YELLOW)Installing binaries...$(COLOR_RESET)"
	@install -d $(DESTDIR)/usr/local/bin
	@install -m 0755 dilithion-node $(DESTDIR)/usr/local/bin/
	@install -m 0755 genesis_gen $(DESTDIR)/usr/local/bin/
	@echo "$(COLOR_GREEN)✓ Installed to /usr/local/bin$(COLOR_RESET)"

help:
	@echo "Dilithion Cryptocurrency - Build System"
	@echo ""
	@echo "$(COLOR_BLUE)Main Targets:$(COLOR_RESET)"
	@echo "  all              - Build dilithion-node and genesis_gen (default)"
	@echo "  dilithion-node   - Build the main node application"
	@echo "  genesis_gen      - Build the genesis block generator"
	@echo ""
	@echo "$(COLOR_BLUE)Test Targets:$(COLOR_RESET)"
	@echo "  tests            - Build all test binaries"
	@echo "  test             - Build and run all tests"
	@echo "  phase1_test      - Build Phase 1 core tests"
	@echo "  miner_tests      - Build Phase 3 mining tests"
	@echo "  wallet_tests     - Build Phase 4 wallet tests"
	@echo "  rpc_tests        - Build Phase 4 RPC tests"
	@echo "  integration_tests- Build Phase 5 integration tests"
	@echo "  net_tests        - Build Phase 2 network tests"
	@echo ""
	@echo "$(COLOR_BLUE)Utility Targets:$(COLOR_RESET)"
	@echo "  depends          - Build RandomX and Dilithium dependencies"
	@echo "  clean            - Remove all built files"
	@echo "  install          - Install binaries to /usr/local/bin"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "$(COLOR_BLUE)Code Quality Targets:$(COLOR_RESET)"
	@echo "  analyze          - Run static analysis (cppcheck)"
	@echo "  lint             - Run linter (clang-tidy)"
	@echo "  memcheck         - Run memory leak detection (valgrind)"
	@echo "  coverage         - Generate code coverage report"
	@echo "  docs             - Generate API documentation (Doxygen)"
	@echo "  quality          - Run analysis checks"
	@echo ""
	@echo "$(COLOR_BLUE)Examples:$(COLOR_RESET)"
	@echo "  make                    # Build main binaries"
	@echo "  make -j8                # Build with 8 parallel jobs"
	@echo "  make tests              # Build all tests"
	@echo "  make test               # Build and run all tests"
	@echo "  make clean all          # Clean rebuild"
	@echo "  make depends all        # Build dependencies and main binaries"
	@echo ""
	@echo "$(COLOR_BLUE)Requirements:$(COLOR_RESET)"
	@echo "  - g++ with C++17 support"
	@echo "  - LevelDB library (apt-get install libleveldb-dev)"
	@echo "  - CMake (for RandomX dependency)"
	@echo ""

# ============================================================================
# Code Quality and Analysis
# ============================================================================

.PHONY: analyze lint memcheck coverage quality docs

# Static analysis with cppcheck
analyze:
	@echo "$(COLOR_YELLOW)Running static analysis...$(COLOR_RESET)"
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all \
			--suppress=missingInclude \
			--suppress=unusedFunction \
			$(INCLUDES) \
			src/ 2> cppcheck-report.txt; \
		cat cppcheck-report.txt; \
		echo "$(COLOR_GREEN)✓ Analysis complete (see cppcheck-report.txt)$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ cppcheck not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Linting with clang-tidy
lint:
	@echo "$(COLOR_YELLOW)Running linter...$(COLOR_RESET)"
	@if command -v clang-tidy >/dev/null 2>&1; then \
		find src -name "*.cpp" -not -path "*/test/*" | while read file; do \
			echo "Checking $$file..."; \
			clang-tidy $$file -- -std=c++17 -I src || true; \
		done; \
		echo "$(COLOR_GREEN)✓ Linting complete$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ clang-tidy not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Memory leak detection
memcheck: tests
	@echo "$(COLOR_YELLOW)Running memory leak detection...$(COLOR_RESET)"
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --show-leak-kinds=all \
			--log-file=valgrind-phase1.txt ./phase1_test; \
		valgrind --leak-check=full --show-leak-kinds=all \
			--log-file=valgrind-wallet.txt ./wallet_tests; \
		echo "$(COLOR_GREEN)✓ Memory check complete$(COLOR_RESET)"; \
		echo "  Reports: valgrind-phase1.txt, valgrind-wallet.txt"; \
	else \
		echo "$(COLOR_YELLOW)⚠ valgrind not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Code coverage
coverage:
	@echo "$(COLOR_YELLOW)Building with coverage...$(COLOR_RESET)"
	@if command -v lcov >/dev/null 2>&1; then \
		$(MAKE) clean; \
		CXXFLAGS="$(CXXFLAGS) --coverage" $(MAKE) tests; \
		echo "$(COLOR_YELLOW)Running tests...$(COLOR_RESET)"; \
		./phase1_test || true; \
		./wallet_tests || true; \
		./crypter_tests || true; \
		./wallet_encryption_integration_tests || true; \
		echo "$(COLOR_YELLOW)Generating coverage report...$(COLOR_RESET)"; \
		lcov --capture --directory . --output-file coverage.info; \
		lcov --remove coverage.info '/usr/*' 'depends/*' 'src/test/*' --output-file coverage-filtered.info; \
		genhtml coverage-filtered.info --output-directory coverage-report; \
		echo "$(COLOR_GREEN)✓ Coverage report: coverage-report/index.html$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ lcov not installed. See docs/STATIC-ANALYSIS.md$(COLOR_RESET)"; \
	fi

# Generate API documentation
docs:
	@echo "$(COLOR_YELLOW)Generating API documentation...$(COLOR_RESET)"
	@if command -v doxygen >/dev/null 2>&1; then \
		doxygen Doxyfile; \
		echo "$(COLOR_GREEN)✓ Documentation generated: docs/api/html/index.html$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ doxygen not installed. Install: sudo apt-get install doxygen$(COLOR_RESET)"; \
	fi

# Run all quality checks
quality: analyze
	@echo "$(COLOR_GREEN)✓ Quality checks complete$(COLOR_RESET)"
	@echo "  Note: Run 'make memcheck' and 'make coverage' separately (time-intensive)"

# ============================================================================
# Fuzz Testing (libFuzzer)
# ============================================================================
#
# ARCHITECTURE: Pre-compiled object file approach
#
# This build system uses pre-compiled object files to avoid linker errors in
# CI environments. The architecture mirrors the proven test_dilithion pattern.
#
# STRUCTURE:
#   1. Fuzzer harness files (.cpp) → compiled WITH sanitizers → harness.o
#   2. Dependency files (.cpp) → compiled WITHOUT sanitizers → deps.o
#   3. Dilithium library (.c) → compiled with gcc → dilithium/*.o
#   4. Link: harness.o + deps.o + dilithium/*.o → fuzzer binary
#
# WHY THIS WORKS:
#   - Make automatically builds all prerequisite .o files first
#   - Fuzzer harness gets proper libFuzzer instrumentation
#   - Dependencies use standard compilation (no ABI issues)
#   - Works identically in local and CI (no cached state needed)
#
# WHY DIRECT .cpp COMPILATION FAILS:
#   - Old approach: fuzz_block: harness.cpp block.cpp ... $(DILITHIUM_OBJECTS)
#   - Clang compiles each .cpp separately without full instrumentation
#   - Linker receives incomplete objects → "undefined reference" errors
#   - Worked locally only due to cached .o files from previous builds
#
# FOR MORE DETAILS: See docs/FUZZING-BUILD-SYSTEM.md
#
# Fuzz test compiler (requires Clang with libFuzzer support)
# Try clang++-14 first, fall back to clang++ (any version), or use environment variable
FUZZ_CXX ?= $(shell command -v clang++-14 2>/dev/null || command -v clang++ 2>/dev/null || echo clang++)
FUZZ_CXXFLAGS := -fsanitize=fuzzer,address,undefined -std=c++17 -O1 -g $(INCLUDES) -DDILITHIUM_MODE=3

# Fuzz test sources (Week 3 Phase 4 - 9 harnesses, 42+ targets)
# Week 6 Phase 3 - Added tx_validation and utxo fuzzers (11 harnesses total)
# Week 7 Phase 3 - Split multi-target fuzzers (20 harnesses total)
FUZZ_SHA3_SOURCE := src/test/fuzz/fuzz_sha3.cpp
FUZZ_TRANSACTION_SOURCE := src/test/fuzz/fuzz_transaction.cpp
FUZZ_BLOCK_SOURCE := src/test/fuzz/fuzz_block.cpp
FUZZ_COMPACTSIZE_SOURCE := src/test/fuzz/fuzz_compactsize.cpp
FUZZ_NETWORK_MSG_SOURCE := src/test/fuzz/fuzz_network_message.cpp
FUZZ_ADDRESS_SOURCE := src/test/fuzz/fuzz_address.cpp
FUZZ_DIFFICULTY_SOURCE := src/test/fuzz/fuzz_difficulty.cpp
FUZZ_SUBSIDY_SOURCE := src/test/fuzz/fuzz_subsidy.cpp
FUZZ_MERKLE_SOURCE := src/test/fuzz/fuzz_merkle.cpp
FUZZ_TX_VALIDATION_SOURCE := src/test/fuzz/fuzz_tx_validation.cpp
FUZZ_UTXO_SOURCE := src/test/fuzz/fuzz_utxo.cpp
# New split fuzzers (Phase 3 - Nov 2025)
FUZZ_ADDRESS_ENCODE_SOURCE := src/test/fuzz/fuzz_address_encode.cpp
FUZZ_ADDRESS_VALIDATE_SOURCE := src/test/fuzz/fuzz_address_validate.cpp
FUZZ_ADDRESS_BECH32_SOURCE := src/test/fuzz/fuzz_address_bech32.cpp
FUZZ_ADDRESS_TYPE_SOURCE := src/test/fuzz/fuzz_address_type.cpp
FUZZ_NETWORK_CREATE_SOURCE := src/test/fuzz/fuzz_network_create.cpp
FUZZ_NETWORK_CHECKSUM_SOURCE := src/test/fuzz/fuzz_network_checksum.cpp
FUZZ_NETWORK_COMMAND_SOURCE := src/test/fuzz/fuzz_network_command.cpp
FUZZ_SIGNATURE_SOURCE := src/test/fuzz/fuzz_signature.cpp
FUZZ_BASE58_SOURCE := src/test/fuzz/fuzz_base58.cpp

# Fuzzer object files (compiled WITH sanitizers) - harness code only
FUZZ_SHA3_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_sha3.o
FUZZ_TRANSACTION_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_transaction.o
FUZZ_BLOCK_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_block.o
FUZZ_COMPACTSIZE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_compactsize.o
FUZZ_NETWORK_MSG_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_message.o
FUZZ_ADDRESS_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address.o
FUZZ_DIFFICULTY_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_difficulty.o
FUZZ_SUBSIDY_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_subsidy.o
FUZZ_MERKLE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_merkle.o
FUZZ_TX_VALIDATION_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_tx_validation.o
FUZZ_UTXO_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_utxo.o
# New split fuzzer objects
FUZZ_ADDRESS_ENCODE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_encode.o
FUZZ_ADDRESS_VALIDATE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_validate.o
FUZZ_ADDRESS_BECH32_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_bech32.o
FUZZ_ADDRESS_TYPE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_address_type.o
FUZZ_NETWORK_CREATE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_create.o
FUZZ_NETWORK_CHECKSUM_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_checksum.o
FUZZ_NETWORK_COMMAND_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_network_command.o
FUZZ_SIGNATURE_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_signature.o
FUZZ_BASE58_OBJ := $(OBJ_DIR)/test/fuzz/fuzz_base58.o

# Common fuzzer dependencies (compiled WITHOUT sanitizers) - linked library code
FUZZ_COMMON_OBJECTS := $(OBJ_DIR)/crypto/sha3.o \
                       $(OBJ_DIR)/primitives/transaction.o \
                       $(OBJ_DIR)/primitives/block.o \
                       $(OBJ_DIR)/core/chainparams.o \
                       $(OBJ_DIR)/crypto/randomx_hash.o

FUZZ_CONSENSUS_OBJECTS := $(OBJ_DIR)/consensus/pow.o \
                          $(OBJ_DIR)/consensus/fees.o \
                          $(OBJ_DIR)/consensus/tx_validation.o \
                          $(OBJ_DIR)/consensus/validation.o

FUZZ_NODE_OBJECTS := $(OBJ_DIR)/node/utxo_set.o

# Fuzz test binaries
FUZZ_SHA3 := fuzz_sha3
FUZZ_TRANSACTION := fuzz_transaction
FUZZ_BLOCK := fuzz_block
FUZZ_COMPACTSIZE := fuzz_compactsize
FUZZ_NETWORK_MSG := fuzz_network_message
FUZZ_ADDRESS := fuzz_address
FUZZ_DIFFICULTY := fuzz_difficulty
FUZZ_SUBSIDY := fuzz_subsidy
FUZZ_MERKLE := fuzz_merkle
FUZZ_TX_VALIDATION := fuzz_tx_validation
FUZZ_UTXO := fuzz_utxo
# New split fuzzer binaries
FUZZ_ADDRESS_ENCODE := fuzz_address_encode
FUZZ_ADDRESS_VALIDATE := fuzz_address_validate
FUZZ_ADDRESS_BECH32 := fuzz_address_bech32
FUZZ_ADDRESS_TYPE := fuzz_address_type
FUZZ_NETWORK_CREATE := fuzz_network_create
FUZZ_NETWORK_CHECKSUM := fuzz_network_checksum
FUZZ_NETWORK_COMMAND := fuzz_network_command
FUZZ_SIGNATURE := fuzz_signature
FUZZ_BASE58 := fuzz_base58

# Build all fuzz tests (requires Clang with libFuzzer)
fuzz: fuzz_sha3 fuzz_transaction fuzz_block fuzz_compactsize fuzz_network_message fuzz_address fuzz_difficulty fuzz_subsidy fuzz_merkle fuzz_tx_validation fuzz_utxo fuzz_address_encode fuzz_address_validate fuzz_address_bech32 fuzz_address_type fuzz_network_create fuzz_network_checksum fuzz_network_command fuzz_signature fuzz_base58
	@echo "$(COLOR_GREEN)✓ All fuzz tests built successfully (20 harnesses, 70+ targets)$(COLOR_RESET)"
	@echo "  Run individual: ./fuzz_sha3, ./fuzz_transaction, ./fuzz_block, etc."
	@echo "  With corpus: ./fuzz_transaction fuzz_corpus/transaction/"
	@echo "  Time limit: ./fuzz_block -max_total_time=60"

# Fuzz Testing (libFuzzer) - Pre-compiled object file architecture
# Uses proven pattern from test_dilithion: harness + dependencies as .o files
# Avoids CI linker errors from direct .cpp compilation with sanitizers

# fuzz_sha3: Minimal dependencies (SHA3 only)
fuzz_sha3: $(FUZZ_SHA3_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_transaction: Block + transaction dependencies
fuzz_transaction: $(FUZZ_TRANSACTION_OBJ) $(FUZZ_COMMON_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (3 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L depends/randomx/build-windows -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_block: Block header dependencies
fuzz_block: $(FUZZ_BLOCK_OBJ) $(FUZZ_COMMON_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (4 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L depends/randomx/build-windows -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_compactsize: No external dependencies
fuzz_compactsize: $(FUZZ_COMPACTSIZE_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (5 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_message: SHA3, block, transaction dependencies
fuzz_network_message: $(FUZZ_NETWORK_MSG_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/primitives/block.o $(OBJ_DIR)/primitives/transaction.o $(OBJ_DIR)/crypto/randomx_hash.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (1 target)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L depends/randomx/build-windows -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address: SHA3 and Base58 dependency
fuzz_address: $(FUZZ_ADDRESS_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/util/base58.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (5 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_difficulty: Consensus dependencies
fuzz_difficulty: $(FUZZ_DIFFICULTY_OBJ) $(FUZZ_COMMON_OBJECTS) $(OBJ_DIR)/consensus/pow.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (6 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L depends/randomx/build-windows -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_subsidy: No external dependencies
fuzz_subsidy: $(FUZZ_SUBSIDY_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (7 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_merkle: SHA3 dependency
fuzz_merkle: $(FUZZ_MERKLE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (7 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_tx_validation: Full consensus + UTXO dependencies
fuzz_tx_validation: $(FUZZ_TX_VALIDATION_OBJ) $(FUZZ_COMMON_OBJECTS) $(FUZZ_CONSENSUS_OBJECTS) $(FUZZ_NODE_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (4 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L depends/randomx/build -lleveldb -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_utxo: Full consensus + UTXO dependencies
fuzz_utxo: $(FUZZ_UTXO_OBJ) $(FUZZ_COMMON_OBJECTS) $(FUZZ_CONSENSUS_OBJECTS) $(FUZZ_NODE_OBJECTS) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@ (4 targets)"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^ -L depends/randomx/build -lleveldb -lrandomx -lpthread
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# ============================================================================
# New Split Fuzzers (Phase 3 - November 2025)
# ============================================================================

# fuzz_address_encode: Base58 encoding with SHA3 checksum
fuzz_address_encode: $(FUZZ_ADDRESS_ENCODE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/util/base58.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address_validate: Address validation and checksum verification
fuzz_address_validate: $(FUZZ_ADDRESS_VALIDATE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(OBJ_DIR)/util/base58.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address_bech32: Bech32 address decoding
fuzz_address_bech32: $(FUZZ_ADDRESS_BECH32_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_address_type: Address type detection
fuzz_address_type: $(FUZZ_ADDRESS_TYPE_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_create: Network message serialization
fuzz_network_create: $(FUZZ_NETWORK_CREATE_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_checksum: Network checksum validation
fuzz_network_checksum: $(FUZZ_NETWORK_CHECKSUM_OBJ) $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_network_command: Network command parsing
fuzz_network_command: $(FUZZ_NETWORK_COMMAND_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_signature: Dilithium signature verification
fuzz_signature: $(FUZZ_SIGNATURE_OBJ) $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# fuzz_base58: Base58 codec testing
fuzz_base58: $(FUZZ_BASE58_OBJ) $(OBJ_DIR)/util/base58.o $(OBJ_DIR)/crypto/sha3.o $(DILITHIUM_OBJECTS)
	@echo "$(COLOR_BLUE)[FUZZ-LINK]$(COLOR_RESET) $@"
	@$(FUZZ_CXX) $(FUZZ_CXXFLAGS) -o $@ $^
	@echo "$(COLOR_GREEN)✓ $@ built$(COLOR_RESET)"

# Run fuzz tests (short run for CI)
run_fuzz: fuzz
	@echo "$(COLOR_YELLOW)Running fuzz tests (60 second each)...$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)Fuzzing SHA-3...$(COLOR_RESET)"
	@timeout 60 ./$(FUZZ_SHA3) || true
	@echo "$(COLOR_GREEN)✓ Fuzz testing complete$(COLOR_RESET)"

# ============================================================================
# Code Coverage (Week 4)
# ============================================================================

# Coverage flags
COVERAGE_CXXFLAGS := --coverage -O0 -g
COVERAGE_LDFLAGS := --coverage

# Build with coverage instrumentation and run tests
coverage: CXXFLAGS += $(COVERAGE_CXXFLAGS)
coverage: LDFLAGS += $(COVERAGE_LDFLAGS)
coverage: clean all
	@echo "$(COLOR_BLUE)[COVERAGE]$(COLOR_RESET) Building with coverage instrumentation..."
	@echo "$(COLOR_YELLOW)Note: test_dilithion not yet implemented$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)[COVERAGE]$(COLOR_RESET) Generating coverage report..."
	@mkdir -p coverage_html
	@if command -v lcov >/dev/null 2>&1; then \
		lcov --capture --directory . --output-file coverage.info --ignore-errors source 2>/dev/null || true; \
		lcov --remove coverage.info '/usr/*' '*/test/*' '*/depends/*' --output-file coverage_filtered.info --ignore-errors unused 2>/dev/null || true; \
		genhtml coverage_filtered.info --output-directory coverage_html --ignore-errors source 2>/dev/null || true; \
		echo "$(COLOR_GREEN)✓ Coverage report generated: coverage_html/index.html$(COLOR_RESET)"; \
		lcov --summary coverage_filtered.info 2>/dev/null || true; \
	else \
		echo "$(COLOR_YELLOW)⚠ lcov not found. Install with: sudo apt-get install lcov$(COLOR_RESET)"; \
	fi

# Generate coverage HTML report (assumes coverage data exists)
coverage-html:
	@echo "$(COLOR_BLUE)[COVERAGE]$(COLOR_RESET) Generating HTML report..."
	@mkdir -p coverage_html
	@if command -v lcov >/dev/null 2>&1 && [ -f coverage.info ]; then \
		genhtml coverage_filtered.info --output-directory coverage_html 2>/dev/null || \
		genhtml coverage.info --output-directory coverage_html 2>/dev/null || true; \
		echo "$(COLOR_GREEN)✓ Coverage report: coverage_html/index.html$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)⚠ No coverage data found. Run 'make coverage' first.$(COLOR_RESET)"; \
	fi

# Clean coverage files
coverage-clean:
	@echo "$(COLOR_BLUE)[CLEAN]$(COLOR_RESET) Removing coverage files..."
	@rm -rf *.gcda *.gcno coverage.info coverage_filtered.info coverage_html
	@find . -name "*.gcda" -delete 2>/dev/null || true
	@find . -name "*.gcno" -delete 2>/dev/null || true
	@echo "$(COLOR_GREEN)✓ Coverage files removed$(COLOR_RESET)"

# ============================================================================
# Debugging
# ============================================================================

print-%:
	@echo '$*=$($*)'

.PHONY: print-% fuzz fuzz_sha3 fuzz_transaction fuzz_block fuzz_compactsize fuzz_network_message fuzz_address fuzz_difficulty fuzz_subsidy fuzz_merkle run_fuzz coverage coverage-html coverage-clean
