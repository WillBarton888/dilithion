#!/usr/bin/env python3
"""Apply BUG #76 fix to server.cpp"""

import re

filepath = "c:/Users/will/dilithion/src/rpc/server.cpp"

# Read file
with open(filepath, 'r') as f:
    content = f.read()

# 1. Add includes after #include <chrono>
include_fix = '''#include <chrono>
#include <thread>  // BUG #76 FIX: For std::this_thread::sleep_for
#include <crypto/randomx_hash.h>  // BUG #76 FIX: For randomx_is_mining_mode_ready()'''

content = content.replace('#include <chrono>', include_fix)

# 2. Add FULL mode wait logic after wallet check, before "Check if already mining"
rpc_fix = '''    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized - need address for coinbase");
    }

    // BUG #76 FIX: Wait for RandomX FULL mode before starting mining
    // Following XMRig's proven pattern: "dataset ready" before thread creation
    // Mining threads created in LIGHT mode get LIGHT VMs and never upgrade
    if (!randomx_is_mining_mode_ready()) {
        std::cout << "[RPC] Waiting for RandomX FULL mode initialization..." << std::endl;
        auto wait_start = std::chrono::steady_clock::now();
        while (!randomx_is_mining_mode_ready() && g_node_state.running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto elapsed = std::chrono::steady_clock::now() - wait_start;
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

            // Show progress every 5 seconds
            if (seconds % 5 == 0 && seconds > 0) {
                std::cout << "[RPC] Still waiting for FULL mode... " << seconds << "s elapsed" << std::endl;
            }

            // Timeout after 120 seconds
            if (seconds > 120) {
                throw std::runtime_error("RandomX FULL mode initialization timeout (120s). Try again later.");
            }
        }
        auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - wait_start).count();
        std::cout << "[RPC] RandomX FULL mode ready (" << wait_time << "s)" << std::endl;
    }

    // Check if already mining'''

old_pattern = '''    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized - need address for coinbase");
    }

    // Check if already mining'''

content = content.replace(old_pattern, rpc_fix)

# Write file
with open(filepath, 'w') as f:
    f.write(content)

print("BUG #76 fix applied successfully!")
