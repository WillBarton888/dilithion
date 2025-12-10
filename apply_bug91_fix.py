#!/usr/bin/env python3
"""Apply BUG #91 fix - SendMessage partial send handling"""

import re

with open('src/net/net.cpp', 'r') as f:
    content = f.read()

old_code = '''        // Send to socket (with 5-second timeout)
        int sent = it->second->Send(data.data(), data.size());
        if (sent != static_cast<int>(data.size())) {
            int error_code = it->second->GetLastError();
            std::string error_str = it->second->GetLastErrorString();

            // Check if this is a timeout error
            bool is_timeout = false;
#ifdef _WIN32
            is_timeout = (error_code == WSAETIMEDOUT);
#else
            is_timeout = (error_code == EAGAIN || error_code == EWOULDBLOCK);
#endif

            if (is_timeout) {
                std::cout << "[P2P] WARNING: Send timeout to peer " << peer_id
                          << " (sent " << sent << " of " << data.size() << " bytes) - continuing to next peer" << std::endl;
            } else {
                std::cout << "[P2P] ERROR: Send failed to peer " << peer_id
                          << " (sent " << sent << " of " << data.size() << " bytes, error: " << error_str << ")" << std::endl;
            }
            // Network: Record send error
            connection_quality.RecordError(peer_id);
            partition_detector.RecordConnectionFailure();
            return false;
        }'''

new_code = '''        // BUG #91 FIX: Use loop to handle partial sends on non-blocking sockets
        // Large messages (like 145KB of headers) may not send in one call
        // when the socket buffer is full. We must wait and retry.
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        int total_sent = 0;
        int max_retries = 100;  // 100 retries * 100ms = 10 seconds max
        int retry_count = 0;

        while (remaining > 0 && retry_count < max_retries) {
            int sent = it->second->Send(ptr, remaining);

            if (sent > 0) {
                ptr += sent;
                remaining -= sent;
                total_sent += sent;
                retry_count = 0;  // Reset retry count on successful send
                continue;
            }

            // sent <= 0: Check for would-block (need to wait) vs real error
            int error_code = it->second->GetLastError();
            bool would_block = false;
#ifdef _WIN32
            would_block = (error_code == WSAEWOULDBLOCK);
#else
            would_block = (error_code == EAGAIN || error_code == EWOULDBLOCK);
#endif

            if (would_block) {
                // Socket buffer full, wait for it to drain
                retry_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // Real error - log and fail
            std::string error_str = it->second->GetLastErrorString();
            std::cout << "[P2P] ERROR: Send failed to peer " << peer_id
                      << " (sent " << total_sent << " of " << data.size()
                      << " bytes, error: " << error_str << ")" << std::endl;
            connection_quality.RecordError(peer_id);
            partition_detector.RecordConnectionFailure();
            return false;
        }

        if (remaining > 0) {
            // Timed out after max retries
            std::cout << "[P2P] WARNING: Send timeout to peer " << peer_id
                      << " (sent " << total_sent << " of " << data.size()
                      << " bytes after " << retry_count << " retries)" << std::endl;
            connection_quality.RecordError(peer_id);
            partition_detector.RecordConnectionFailure();
            return false;
        }'''

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('src/net/net.cpp', 'w') as f:
        f.write(content)
    print("BUG #91 fix applied successfully!")
else:
    print("ERROR: Old code not found - may have already been applied or file changed")
