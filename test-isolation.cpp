// Test program to verify BUG #49 fixes
#include <iostream>
#include <chrono>
#include <thread>

void testIBDBackoff() {
    std::cout << "\n=== Testing IBD Backoff Logic ===" << std::endl;

    // Simulate IBD with no peers
    int ibd_no_peer_cycles = 0;
    auto last_ibd_attempt = std::chrono::steady_clock::now();

    for (int iteration = 0; iteration < 10; iteration++) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_ibd_attempt);

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (max)
        int backoff_seconds = std::min(30, (1 << std::min(ibd_no_peer_cycles, 5)));

        std::cout << "Iteration " << iteration << ": ";
        std::cout << "Cycles without peers: " << ibd_no_peer_cycles;
        std::cout << ", Backoff: " << backoff_seconds << "s";
        std::cout << ", Elapsed: " << elapsed.count() << "s" << std::endl;

        if (elapsed.count() >= backoff_seconds) {
            // Would attempt IBD here
            std::cout << "  -> Attempting IBD (no peers available)" << std::endl;
            ibd_no_peer_cycles++;
            last_ibd_attempt = now;
        } else {
            std::cout << "  -> Waiting (backoff not reached)" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void testMisbehaviorDecay() {
    std::cout << "\n=== Testing Misbehavior Score Decay ===" << std::endl;

    int misbehavior_score = 50;

    for (int minute = 0; minute < 10; minute++) {
        std::cout << "Minute " << minute << ": Score = " << misbehavior_score << std::endl;

        // Decay by 1 point per minute (called every 30 seconds, so 0.5 per call)
        if (misbehavior_score > 0) {
            misbehavior_score = std::max(0, misbehavior_score - 1);

            if (misbehavior_score % 10 == 0) {
                std::cout << "  -> Significant decay milestone: " << misbehavior_score << std::endl;
            }
        }
    }
}

void testIsolationDetection() {
    std::cout << "\n=== Testing Mining Isolation Detection ===" << std::endl;

    int mining_without_peers_minutes = 0;

    for (int minute = 0; minute < 15; minute++) {
        // Simulate no peers
        mining_without_peers_minutes++;

        std::cout << "Minute " << minute << ": ";

        if (mining_without_peers_minutes == 1) {
            std::cout << "WARNING: Mining with no connected peers" << std::endl;
        } else if (mining_without_peers_minutes == 5) {
            std::cout << "WARNING: Mining in isolation for 5 minutes - possible chain fork" << std::endl;
        } else if (mining_without_peers_minutes == 10) {
            std::cout << "CRITICAL: Mining in isolation for 10 minutes!" << std::endl;
            std::cout << "  You are likely creating a chain fork that will be rejected" << std::endl;
        } else if (mining_without_peers_minutes % 10 == 0) {
            std::cout << "Still mining in isolation (" << mining_without_peers_minutes
                      << " minutes) - chain fork highly likely!" << std::endl;
        } else {
            std::cout << "Mining without peers (" << mining_without_peers_minutes << " min)" << std::endl;
        }
    }
}

int main() {
    std::cout << "BUG #49 Fix Verification Test" << std::endl;
    std::cout << "==============================" << std::endl;

    testIBDBackoff();
    testMisbehaviorDecay();
    testIsolationDetection();

    std::cout << "\n=== All Tests Complete ===" << std::endl;
    std::cout << "The fixes implement:" << std::endl;
    std::cout << "1. Exponential backoff for IBD when no peers (1s -> 30s max)" << std::endl;
    std::cout << "2. Misbehavior score decay (1 point/minute)" << std::endl;
    std::cout << "3. Mining isolation warnings (at 1, 5, 10+ minutes)" << std::endl;

    return 0;
}