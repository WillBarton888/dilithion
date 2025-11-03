# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Base test framework for Dilithion functional tests

Based on Bitcoin Core's BitcoinTestFramework pattern with adaptations
for Dilithion's post-quantum architecture.
"""

import argparse
import logging
import os
import sys
import tempfile
import time
import subprocess
from typing import List, Optional
from .util import (
    assert_equal,
    wait_until,
    AssertionError as TestAssertionError
)


class TestStatus:
    """Test execution status tracking"""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class DilithionTestFramework:
    """Base class for Dilithion functional tests

    Provides infrastructure for:
    - Node management (start/stop)
    - RPC communication
    - Block generation
    - Test lifecycle (setup/teardown)
    - Logging

    Usage:
        class MyTest(DilithionTestFramework):
            def set_test_params(self):
                self.num_nodes = 2
                self.setup_clean_chain = True

            def run_test(self):
                # Test logic here
                self.log.info("Running test...")

        if __name__ == "__main__":
            MyTest().main()
    """

    def __init__(self):
        """Initialize test framework"""
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.nodes = []
        self.mocktime = 0
        self.rpc_timeout = 60
        self.supports_cli = True
        self.bind_to_localhost_only = True

        # Test metadata
        self.test_name = self.__class__.__name__
        self.status = None

        # Logging
        self.log = logging.getLogger(f"TestFramework.{self.test_name}")

        # Temporary directory for test data
        self.options = None
        self.tmpdir = None

    def set_test_params(self):
        """Set test parameters (override in subclass)

        Should set:
            self.num_nodes - Number of nodes to run
            self.setup_clean_chain - Start with fresh blockchain
        """
        raise NotImplementedError("Test must implement set_test_params()")

    def skip_test_if_missing_module(self):
        """Skip test if required module is missing (override if needed)"""
        pass

    def setup_chain(self):
        """Set up blockchain before nodes start (override if needed)"""
        pass

    def setup_network(self):
        """Set up network topology (override if needed)

        Default: Start all nodes
        """
        self.setup_nodes()

    def setup_nodes(self):
        """Start all nodes with default configuration"""
        self.log.info(f"Starting {self.num_nodes} node(s)...")

        for i in range(self.num_nodes):
            self.log.info(f"Starting node {i}")
            # TODO: Implement actual node starting
            # For now, create placeholder
            self.nodes.append(TestNode(i, self.tmpdir, self))

        self.log.info("All nodes started successfully")

    def run_test(self):
        """Run the actual test logic (override in subclass)"""
        raise NotImplementedError("Test must implement run_test()")

    def stop_nodes(self):
        """Stop all running nodes"""
        self.log.info("Stopping all nodes...")

        for i, node in enumerate(self.nodes):
            try:
                self.log.info(f"Stopping node {i}")
                node.stop()
            except Exception as e:
                self.log.warning(f"Error stopping node {i}: {e}")

        self.nodes = []
        self.log.info("All nodes stopped")

    def setup(self):
        """Set up test environment"""
        # Create temporary directory
        if not self.options.tmpdir:
            self.tmpdir = tempfile.mkdtemp(prefix=f"dilithion_test_{self.test_name}_")
            self.log.info(f"Temporary test directory: {self.tmpdir}")
        else:
            self.tmpdir = self.options.tmpdir
            os.makedirs(self.tmpdir, exist_ok=True)

        # Set up chain
        self.setup_chain()

        # Set up network
        self.setup_network()

    def shutdown(self):
        """Clean up test environment"""
        self.log.info("Shutting down test framework...")

        # Stop nodes
        self.stop_nodes()

        # Clean up temporary directory if not preserving
        if not self.options.nocleanup:
            import shutil
            try:
                shutil.rmtree(self.tmpdir)
                self.log.info(f"Removed temporary directory: {self.tmpdir}")
            except Exception as e:
                self.log.warning(f"Failed to remove tmpdir: {e}")

    def main(self):
        """Main test execution entry point"""
        # Parse command line arguments
        parser = argparse.ArgumentParser(usage=f"%(prog)s [options]")
        parser.add_argument(
            "--nocleanup",
            dest="nocleanup",
            default=False,
            action="store_true",
            help="Leave test data directory on exit"
        )
        parser.add_argument(
            "--tmpdir",
            dest="tmpdir",
            default="",
            help="Root directory for test data"
        )
        parser.add_argument(
            "-v", "--verbose",
            dest="verbose",
            default=False,
            action="store_true",
            help="Enable verbose logging"
        )
        parser.add_argument(
            "--tracerpc",
            dest="tracerpc",
            default=False,
            action="store_true",
            help="Print RPC calls"
        )

        self.options = parser.parse_args()

        # Set up logging
        log_level = logging.DEBUG if self.options.verbose else logging.INFO
        logging.basicConfig(
            format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
            level=log_level
        )

        # Run test
        success = False
        try:
            self.log.info(f"Starting test: {self.test_name}")
            self.log.info("=" * 80)

            # Check for missing modules
            self.skip_test_if_missing_module()

            # Set test parameters
            self.set_test_params()

            # Set up test environment
            self.setup()

            # Run the actual test
            self.run_test()

            # If we got here, test passed
            self.status = TestStatus.PASSED
            success = True

            self.log.info("=" * 80)
            self.log.info(f"Test {self.test_name}: PASSED")

        except TestAssertionError as e:
            self.status = TestStatus.FAILED
            self.log.error("=" * 80)
            self.log.error(f"Test {self.test_name}: FAILED")
            self.log.error(f"Assertion failed: {e}")

        except Exception as e:
            self.status = TestStatus.FAILED
            self.log.error("=" * 80)
            self.log.error(f"Test {self.test_name}: FAILED")
            self.log.error(f"Unexpected exception: {e}")
            import traceback
            self.log.error(traceback.format_exc())

        finally:
            # Always clean up
            try:
                self.shutdown()
            except Exception as e:
                self.log.error(f"Error during shutdown: {e}")

        # Exit with appropriate code
        sys.exit(0 if success else 1)


class TestNode:
    """Represents a Dilithion node in the test framework

    Provides:
    - Node process management
    - RPC interface
    - Block generation helpers
    """

    def __init__(self, index: int, datadir: str, test_framework):
        """Initialize test node

        Args:
            index: Node index number
            datadir: Data directory path
            test_framework: Parent test framework instance
        """
        self.index = index
        self.datadir = os.path.join(datadir, f"node{index}")
        self.test_framework = test_framework
        self.process = None
        self.rpc_port = 8332 + index
        self.p2p_port = 8333 + index

        # Create data directory
        os.makedirs(self.datadir, exist_ok=True)

        # TODO: Start actual dilithion-node process
        # For now, this is a placeholder

    def start(self, extra_args: Optional[List[str]] = None):
        """Start the node process

        Args:
            extra_args: Additional command line arguments
        """
        if extra_args is None:
            extra_args = []

        # TODO: Implement actual node starting
        # Example:
        # self.process = subprocess.Popen([
        #     './dilithion-node',
        #     f'-datadir={self.datadir}',
        #     f'-rpcport={self.rpc_port}',
        #     f'-port={self.p2p_port}',
        #     *extra_args
        # ])

        pass

    def stop(self):
        """Stop the node process"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None

    def wait_for_rpc_connection(self):
        """Wait for RPC interface to be available"""
        def check_rpc():
            # TODO: Implement actual RPC check
            # For now, just wait a bit
            return True

        wait_until(check_rpc, timeout=60, label=f"node{self.index} RPC connection")

    # RPC method placeholders (to be implemented)
    def getblockcount(self) -> int:
        """Get current block count"""
        # TODO: Implement actual RPC call
        return 0

    def getbestblockhash(self) -> str:
        """Get best block hash"""
        # TODO: Implement actual RPC call
        return "0" * 64

    def getblock(self, blockhash: str, verbosity: int = 1):
        """Get block by hash"""
        # TODO: Implement actual RPC call
        return {}

    def generatetoaddress(self, nblocks: int, address: str) -> List[str]:
        """Generate blocks to address"""
        # TODO: Implement actual RPC call
        return []

    def sendtoaddress(self, address: str, amount: float) -> str:
        """Send DIL to address"""
        # TODO: Implement actual RPC call
        return "0" * 64

    def getnewaddress(self) -> str:
        """Get new address from wallet"""
        # TODO: Implement actual RPC call
        return "dilithion_address_placeholder"

    def getbalance(self) -> float:
        """Get wallet balance"""
        # TODO: Implement actual RPC call
        return 0.0
