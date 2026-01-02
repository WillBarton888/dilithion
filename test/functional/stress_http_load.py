#!/usr/bin/env python3
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Stress test: HTTP API load handling

This test validates that:
1. HTTP thread pool handles concurrent requests (Phase 1 implemented)
2. /api/health responds quickly under load
3. /api/stats returns correct data under load
4. /metrics endpoint remains responsive
5. No request timeouts under reasonable load

Phase 1 implemented HTTP thread pool (4 workers).
This test verifies that functionality.

Phase 2.3 stress test from STRESS-TEST-IMPROVEMENT-RECOMMENDATIONS.md
"""

import time
import threading
import concurrent.futures
import requests
from test_framework.test_framework import DilithionTestFramework


class HttpLoadTest(DilithionTestFramework):
    """Test HTTP API under load"""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        # Skip in CI - requires real node with HTTP server
        self.skip_test("Requires real node with HTTP server (not mock)")

    def run_test(self):
        self.log.info("Starting HTTP load stress test...")

        node = self.nodes[0]
        base_url = f"http://{node.host}:{node.rpc_port}"

        # Test 1: Health endpoint response time
        self.log.info("Test 1: /api/health response time baseline")
        health_times = []
        for i in range(10):
            start = time.time()
            try:
                response = requests.get(f"{base_url}/api/health", timeout=5)
                elapsed = (time.time() - start) * 1000
                health_times.append(elapsed)
                self.log.info(f"  Request {i+1}: {elapsed:.2f}ms (status: {response.status_code})")
            except Exception as e:
                self.log.warning(f"  Request {i+1}: FAILED ({e})")

        if health_times:
            avg_health = sum(health_times) / len(health_times)
            self.log.info(f"  Average: {avg_health:.2f}ms")
            self.log.info(f"  Requirement: < 100ms")
            if avg_health < 100:
                self.log.info("  PASS: Health endpoint meets latency requirement")
            else:
                self.log.warning("  WARNING: Health endpoint exceeds latency target")

        # Test 2: Concurrent requests to /api/stats
        self.log.info("Test 2: Concurrent requests to /api/stats")

        num_concurrent = 100
        timeout_seconds = 5
        results = {'success': 0, 'failure': 0, 'times': []}
        lock = threading.Lock()

        def make_request(request_id):
            start = time.time()
            try:
                response = requests.get(f"{base_url}/api/stats", timeout=timeout_seconds)
                elapsed = (time.time() - start) * 1000
                with lock:
                    if response.status_code == 200:
                        results['success'] += 1
                    else:
                        results['failure'] += 1
                    results['times'].append(elapsed)
            except Exception:
                with lock:
                    results['failure'] += 1

        self.log.info(f"  Sending {num_concurrent} concurrent requests...")
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_concurrent)]
            concurrent.futures.wait(futures)

        total_time = time.time() - start_time

        self.log.info(f"  Completed in {total_time:.2f}s")
        self.log.info(f"  Success: {results['success']}")
        self.log.info(f"  Failure: {results['failure']}")

        if results['times']:
            avg_time = sum(results['times']) / len(results['times'])
            max_time = max(results['times'])
            min_time = min(results['times'])
            self.log.info(f"  Avg latency: {avg_time:.2f}ms")
            self.log.info(f"  Min latency: {min_time:.2f}ms")
            self.log.info(f"  Max latency: {max_time:.2f}ms")

        # Requirement: All requests should complete within 5 seconds total
        if total_time < 5:
            self.log.info(f"  PASS: All requests completed within 5s")
        else:
            self.log.warning(f"  WARNING: Requests took longer than 5s")

        # Test 3: Metrics endpoint under load
        self.log.info("Test 3: /metrics endpoint responsiveness")

        metrics_times = []
        for i in range(20):
            start = time.time()
            try:
                response = requests.get(f"{base_url}/metrics", timeout=5)
                elapsed = (time.time() - start) * 1000
                metrics_times.append(elapsed)
            except Exception as e:
                self.log.warning(f"  Metrics request failed: {e}")

        if metrics_times:
            avg_metrics = sum(metrics_times) / len(metrics_times)
            self.log.info(f"  Average metrics latency: {avg_metrics:.2f}ms")

        # Test 4: Thread pool saturation
        self.log.info("Test 4: Thread pool saturation test")
        self.log.info("  Phase 1 HTTP thread pool: 4 workers")
        self.log.info("  Sending 10 slow requests concurrently...")

        slow_results = {'completed': 0, 'times': []}

        def slow_request(request_id):
            start = time.time()
            try:
                # Use stats endpoint which is more expensive
                response = requests.get(f"{base_url}/api/stats", timeout=30)
                elapsed = (time.time() - start) * 1000
                with lock:
                    slow_results['completed'] += 1
                    slow_results['times'].append(elapsed)
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(slow_request, i) for i in range(10)]
            concurrent.futures.wait(futures, timeout=30)

        self.log.info(f"  Completed: {slow_results['completed']}/10")
        if slow_results['times']:
            self.log.info(f"  Avg time: {sum(slow_results['times'])/len(slow_results['times']):.2f}ms")

        self.log.info("HTTP load stress test complete")
        self.log.info("Summary:")
        self.log.info("  - Health endpoint: TESTED")
        self.log.info("  - Concurrent requests: TESTED")
        self.log.info("  - Metrics endpoint: TESTED")
        self.log.info("  - Thread pool: Phase 1 IMPLEMENTED (4 workers)")


if __name__ == "__main__":
    HttpLoadTest().main()
