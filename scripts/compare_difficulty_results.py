#!/usr/bin/env python3
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""
Difficulty Determinism Cross-Platform Comparison Tool

CRITICAL CONSENSUS VALIDATION

This script compares difficulty calculation results from multiple platforms
to ensure consensus across all architectures, operating systems, and compilers.

Usage:
    python3 compare_difficulty_results.py [result_files...]

Example:
    python3 compare_difficulty_results.py \
        difficulty_results_ubuntu_gcc.json \
        difficulty_results_ubuntu_clang.json \
        difficulty_results_windows_msvc.json \
        difficulty_results_macos_clang.json

Exit codes:
    0: All platforms agree (consensus achieved)
    1: Platforms disagree (CRITICAL - consensus fork risk)
    2: Missing or invalid files

Priority: P0 - CRITICAL
Related: CRITICAL-DIFFICULTY-DETERMINISM-PLAN.md
"""

import json
import sys
import os
from typing import List, Dict, Any
from collections import defaultdict


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(message: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{message:^80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.ENDC}\n")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.FAIL}✗ ERROR: {message}{Colors.ENDC}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠ WARNING: {message}{Colors.ENDC}")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def load_result_file(filename: str) -> Dict[str, Any]:
    """Load a result JSON file

    Args:
        filename: Path to JSON result file

    Returns:
        Parsed JSON data

    Raises:
        ValueError: If file cannot be loaded or parsed
    """
    if not os.path.exists(filename):
        raise ValueError(f"File not found: {filename}")

    try:
        with open(filename, 'r') as f:
            data = json.load(f)

        # Validate required fields
        if 'platform_info' not in data:
            raise ValueError(f"Missing platform_info in {filename}")
        if 'results' not in data:
            raise ValueError(f"Missing results in {filename}")

        return data

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {filename}: {e}")


def compare_results(platforms: List[Dict[str, Any]]) -> bool:
    """Compare results from multiple platforms

    Args:
        platforms: List of platform result data

    Returns:
        True if all platforms agree, False otherwise
    """
    if len(platforms) < 2:
        print_warning("Need at least 2 platforms to compare")
        return True

    print_header("CROSS-PLATFORM COMPARISON")

    # Group results by test_id
    results_by_test = defaultdict(list)

    for platform_data in platforms:
        platform_name = platform_data['platform_info']

        for result in platform_data['results']:
            test_id = result['test_id']
            results_by_test[test_id].append({
                'platform': platform_name,
                'output_compact': result['output_compact'],
                'output_target_hex': result['output_target_hex'],
                'input_compact': result['input_compact'],
                'actual_timespan': result['actual_timespan'],
                'target_timespan': result['target_timespan'],
            })

    # Check each test for agreement
    all_agree = True
    disagreements = []

    for test_id in sorted(results_by_test.keys()):
        results = results_by_test[test_id]

        # Get unique output compacts
        unique_compacts = set(r['output_compact'] for r in results)

        if len(unique_compacts) == 1:
            # All platforms agree
            print(f"Test {test_id}: {Colors.OKGREEN}✓ CONSENSUS{Colors.ENDC}")
            print(f"  All {len(results)} platforms agree: {unique_compacts.pop()}")
        else:
            # Platforms disagree - CRITICAL!
            all_agree = False
            print(f"Test {test_id}: {Colors.FAIL}✗ MISMATCH{Colors.ENDC}")
            print(f"  {Colors.BOLD}CRITICAL: Platforms disagree on difficulty!{Colors.ENDC}")

            # Show disagreement details
            print(f"\n  Input parameters:")
            print(f"    Input compact: {results[0]['input_compact']}")
            print(f"    Actual timespan: {results[0]['actual_timespan']}")
            print(f"    Target timespan: {results[0]['target_timespan']}")

            print(f"\n  Platform results:")
            for result in results:
                print(f"    {result['platform']:40} → {result['output_compact']}")

            print(f"\n  Full target hashes:")
            for result in results:
                print(f"    {result['platform']:40}")
                print(f"      {result['output_target_hex']}")

            disagreements.append({
                'test_id': test_id,
                'results': results
            })

        print()

    # Summary
    print_header("SUMMARY")

    print(f"Platforms compared: {len(platforms)}")
    for platform_data in platforms:
        print(f"  - {platform_data['platform_info']}")

    print(f"\nTests analyzed: {len(results_by_test)}")

    if all_agree:
        print_success(f"ALL PLATFORMS AGREE - Consensus achieved!")
        print(f"\n{Colors.OKGREEN}✓ Cross-platform determinism verified{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✓ No consensus fork risk detected{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✓ Safe for mainnet deployment{Colors.ENDC}")
    else:
        print_error(f"{len(disagreements)} test(s) show platform disagreement")
        print(f"\n{Colors.FAIL}{Colors.BOLD}⚠ CRITICAL CONSENSUS FORK RISK!{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠ Platforms calculate different difficulty values{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠ This will cause chain splits on mainnet{Colors.ENDC}")
        print(f"{Colors.FAIL}⚠ MAINNET LAUNCH IS BLOCKED{Colors.ENDC}")

        # Write disagreement report
        report_filename = "difficulty_mismatch.txt"
        with open(report_filename, 'w') as f:
            f.write("CRITICAL: DIFFICULTY CALCULATION PLATFORM MISMATCH\n")
            f.write("="*70 + "\n\n")

            f.write(f"Platforms compared: {len(platforms)}\n")
            for platform_data in platforms:
                f.write(f"  - {platform_data['platform_info']}\n")

            f.write(f"\nTests with disagreement: {len(disagreements)}\n\n")

            for disagreement in disagreements:
                f.write(f"Test: {disagreement['test_id']}\n")
                f.write(f"  Input compact: {disagreement['results'][0]['input_compact']}\n")
                f.write(f"  Timespan: {disagreement['results'][0]['actual_timespan']} / ")
                f.write(f"{disagreement['results'][0]['target_timespan']}\n\n")

                f.write(f"  Platform results:\n")
                for result in disagreement['results']:
                    f.write(f"    {result['platform']:40} → {result['output_compact']}\n")

                f.write("\n")

            f.write("\nACTION REQUIRED:\n")
            f.write("  1. Debug the arithmetic functions in pow.cpp\n")
            f.write("  2. Consider using Bitcoin Core's ArithU256 class\n")
            f.write("  3. Re-test on all platforms\n")
            f.write("  4. DO NOT PROCEED TO MAINNET UNTIL RESOLVED\n")

        print(f"\nDisagreement report saved to: {report_filename}")

    return all_agree


def generate_comparison_matrix(platforms: List[Dict[str, Any]]):
    """Generate a comparison matrix showing all results

    Args:
        platforms: List of platform result data
    """
    print_header("DETAILED COMPARISON MATRIX")

    # Get all test IDs
    test_ids = set()
    for platform_data in platforms:
        for result in platform_data['results']:
            test_ids.add(result['test_id'])

    test_ids = sorted(test_ids)

    # Build matrix
    print(f"{'Test ID':30} | ", end='')
    for platform_data in platforms:
        platform_short = platform_data['platform_info'][:20]
        print(f"{platform_short:22} | ", end='')
    print()

    print("-" * (30 + (24 * len(platforms)) + 3))

    for test_id in test_ids:
        print(f"{test_id:30} | ", end='')

        # Get result for each platform
        for platform_data in platforms:
            result = next(
                (r for r in platform_data['results'] if r['test_id'] == test_id),
                None
            )

            if result:
                print(f"{result['output_compact']:22} | ", end='')
            else:
                print(f"{'MISSING':22} | ", end='')

        print()


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python3 compare_difficulty_results.py <result_files...>")
        print("\nExample:")
        print("  python3 compare_difficulty_results.py \\")
        print("      difficulty_results_ubuntu_gcc.json \\")
        print("      difficulty_results_ubuntu_clang.json \\")
        print("      difficulty_results_windows_msvc.json")
        sys.exit(2)

    print_header("DIFFICULTY DETERMINISM CROSS-PLATFORM VALIDATOR")

    print(f"{Colors.BOLD}CRITICAL CONSENSUS VALIDATION{Colors.ENDC}")
    print(f"This tool validates that ALL platforms calculate identical difficulty values\n")

    # Load all result files
    platforms = []
    for filename in sys.argv[1:]:
        print(f"Loading: {filename}...", end=' ')

        try:
            data = load_result_file(filename)
            platforms.append(data)
            print(f"{Colors.OKGREEN}✓{Colors.ENDC}")
            print(f"  Platform: {data['platform_info']}")
            print(f"  Tests: {data['test_count']}")
            print(f"  Passed: {data['passed_count']}")

        except ValueError as e:
            print(f"{Colors.FAIL}✗{Colors.ENDC}")
            print_error(str(e))
            sys.exit(2)

        print()

    if len(platforms) == 0:
        print_error("No valid result files loaded")
        sys.exit(2)

    # Compare results
    all_agree = compare_results(platforms)

    # Generate comparison matrix
    if len(platforms) >= 2:
        generate_comparison_matrix(platforms)

    # Exit with appropriate code
    if all_agree:
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}✓ VALIDATION PASSED{Colors.ENDC}")
        sys.exit(0)
    else:
        print(f"\n{Colors.FAIL}{Colors.BOLD}✗ VALIDATION FAILED{Colors.ENDC}")
        print(f"{Colors.FAIL}  MAINNET LAUNCH BLOCKED{Colors.ENDC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
