#!/usr/bin/env python3
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Example functional test demonstrating the test framework

This test serves as a template and documentation for writing
new functional tests for Dilithion.
"""

from test_framework.test_framework import DilithionTestFramework
from test_framework.util import assert_equal, assert_greater_than


class ExampleTest(DilithionTestFramework):
    """Example test class

    This demonstrates the basic structure of a Dilithion functional test.
    """

    def set_test_params(self):
        """Set test-specific parameters"""
        # Number of nodes to run
        self.num_nodes = 1

        # Whether to start with a fresh blockchain
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        """Skip test if required modules are missing"""
        # Example: skip if wallet is not compiled
        # self.skip_if_no_wallet()
        pass

    def run_test(self):
        """Main test logic"""
        self.log.info("Starting example test...")

        # Get reference to first node
        node = self.nodes[0]

        # Example: Check initial block count
        initial_blocks = node.getblockcount()
        self.log.info(f"Initial block count: {initial_blocks}")

        # Example assertion
        assert_equal(initial_blocks, 0, "Chain should start at genesis")

        # TODO: When node implementation is ready, test actual functionality
        # Example:
        # - Generate blocks
        # - Create transactions
        # - Test consensus rules
        # - Verify state

        self.log.info("Example test completed successfully")


if __name__ == "__main__":
    ExampleTest().main()
