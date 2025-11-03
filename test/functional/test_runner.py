#!/usr/bin/env python3
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Test runner for Dilithion functional tests

Executes all functional tests and reports results.
Based on Bitcoin Core's test_runner.py pattern.
"""

import argparse
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import List, Tuple


# ANSI color codes for terminal output
class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# List of all functional tests
# Format: "test_name.py"
ALL_TESTS = [
    "example_test.py",

    # P0 Critical Consensus Tests (Week 3 Phase 2)
    "feature_merkle_root.py",   # Merkle root validation
    "feature_difficulty.py",    # Difficulty adjustment (2016 blocks)
    "feature_subsidy.py",       # Coinbase subsidy halving (210k blocks)
    "feature_pow.py",           # Proof-of-Work (RandomX)
    "feature_signatures.py",    # Dilithium3 signatures
    "feature_timestamps.py",    # Timestamp validation (MTP)

    # P1 High-Priority Tests (Week 3 Phase 3)
    "feature_tx_serialization.py",  # Transaction serialization
    "wallet_multi_input.py",        # Multi-input wallet signing
    "mempool_double_spend.py",      # Mempool double-spend detection
    "p2p_message_checksum.py",      # Network message checksums
    "interface_rpc_validation.py",  # RPC input validation

    # P2 Edge Case Tests (Week 3 Phase 4)
    "feature_block_validation.py",  # Block validation edge cases
    "feature_chain_reorg.py",       # Chain reorganization handling
]


def print_header(message: str):
    """Print formatted header"""
    print(f"\n{Color.BOLD}{Color.HEADER}{'='*80}{Color.ENDC}")
    print(f"{Color.BOLD}{Color.HEADER}{message:^80}{Color.ENDC}")
    print(f"{Color.BOLD}{Color.HEADER}{'='*80}{Color.ENDC}\n")


def print_result(test_name: str, passed: bool, duration: float):
    """Print test result"""
    status = f"{Color.OKGREEN}PASSED{Color.ENDC}" if passed else f"{Color.FAIL}FAILED{Color.ENDC}"
    print(f"  {test_name:.<60} {status} ({duration:.2f}s)")


def run_test(test_path: Path, verbose: bool = False) -> Tuple[bool, float]:
    """Run a single test

    Args:
        test_path: Path to test file
        verbose: Enable verbose output

    Returns:
        Tuple of (success, duration)
    """
    start_time = time.time()

    try:
        cmd = [sys.executable, str(test_path)]
        if verbose:
            cmd.append("--verbose")

        result = subprocess.run(
            cmd,
            capture_output=not verbose,
            text=True,
            timeout=300  # 5 minute timeout per test
        )

        duration = time.time() - start_time
        return result.returncode == 0, duration

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        return False, duration
    except Exception as e:
        print(f"{Color.FAIL}Error running test: {e}{Color.ENDC}")
        duration = time.time() - start_time
        return False, duration


def main():
    """Main test runner entry point"""
    parser = argparse.ArgumentParser(
        description="Dilithion functional test runner",
        usage="%(prog)s [options]"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose test output"
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="",
        help="Only run tests matching this pattern"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all tests and exit"
    )

    args = parser.parse_args()

    # Get test directory
    test_dir = Path(__file__).parent

    # Filter tests
    tests_to_run = ALL_TESTS
    if args.filter:
        tests_to_run = [t for t in ALL_TESTS if args.filter in t]

    # List tests if requested
    if args.list:
        print("Available tests:")
        for test in ALL_TESTS:
            marker = "✓" if test in tests_to_run else " "
            print(f"  [{marker}] {test}")
        sys.exit(0)

    # Print header
    print_header("Dilithion Functional Test Suite")
    print(f"Running {len(tests_to_run)} test(s)...\n")

    # Run tests
    results = []
    start_time = time.time()

    for test_name in tests_to_run:
        test_path = test_dir / test_name

        if not test_path.exists():
            print(f"{Color.WARNING}Warning: Test file not found: {test_name}{Color.ENDC}")
            continue

        passed, duration = run_test(test_path, args.verbose)
        results.append((test_name, passed, duration))
        print_result(test_name, passed, duration)

    total_duration = time.time() - start_time

    # Print summary
    passed_count = sum(1 for _, passed, _ in results if passed)
    failed_count = len(results) - passed_count

    print(f"\n{Color.BOLD}{'='*80}{Color.ENDC}")
    print(f"{Color.BOLD}Summary:{Color.ENDC}")
    print(f"  Total:   {len(results)} tests")
    print(f"  {Color.OKGREEN}Passed:  {passed_count}{Color.ENDC}")
    if failed_count > 0:
        print(f"  {Color.FAIL}Failed:  {failed_count}{Color.ENDC}")
    print(f"  Time:    {total_duration:.2f}s")
    print(f"{Color.BOLD}{'='*80}{Color.ENDC}\n")

    # Exit with appropriate code
    sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
    main()
