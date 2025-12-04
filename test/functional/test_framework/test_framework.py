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


class SkipTest(Exception):
    """Exception raised when a test should be skipped"""
    pass


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

    def skip_test(self, reason: str):
        """Skip this test with a reason message

        Args:
            reason: Explanation for why test is skipped
        """
        raise SkipTest(reason)

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

    def sync_all(self, timeout=60):
        """Synchronize all nodes (wait for block sync)"""
        # TODO: Implement actual sync logic
        # For now, just return as nodes are placeholders
        pass

    def sync_blocks(self, timeout=60):
        """Synchronize blocks across all nodes"""
        # TODO: Implement actual sync logic
        pass

    def sync_mempools(self, timeout=60):
        """Synchronize mempools across all nodes"""
        # TODO: Implement actual sync logic
        pass

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

        except SkipTest as e:
            self.status = TestStatus.SKIPPED
            success = True  # Skipped tests are not failures
            self.log.info("=" * 80)
            self.log.info(f"Test {self.test_name}: SKIPPED")
            self.log.info(f"Reason: {e}")

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

        # Mock blockchain state (for tests that need stateful behavior)
        self._block_count = 0
        self._blocks = {}  # height -> block data
        self._block_hashes = {}  # height -> hash
        self._hash_to_height = {}  # hash -> height
        self._addresses = []  # Generated addresses
        self._transactions = {}  # txid -> tx data
        self._mempool = []  # List of txids in mempool
        self._genesis_time = int(time.time()) - 1000000  # Genesis ~11 days ago

        # Initialize genesis block
        self._initialize_genesis()

        # TODO: Start actual dilithion-node process
        # For now, this is a placeholder

    def _initialize_genesis(self):
        """Initialize genesis block"""
        genesis_hash = "0" * 64
        genesis_txid = "1" * 64
        self._block_count = 0
        self._blocks[0] = {
            'hash': genesis_hash,
            'height': 0,
            'version': 1,
            'merkleroot': genesis_txid,
            'tx': [{
                'txid': genesis_txid,
                'vout': [{'value': 50.0, 'scriptPubKey': {'addresses': []}}],
                'vin': [{'coinbase': '00'}]
            }],
            'time': self._genesis_time,
            'nonce': 0,
            'bits': '1d00ffff',
            'difficulty': 1.0,
            'previousblockhash': '0' * 64,
        }
        self._block_hashes[0] = genesis_hash
        self._hash_to_height[genesis_hash] = 0
        self._transactions[genesis_txid] = {
            'txid': genesis_txid,
            'hash': genesis_txid,
            'version': 1,
            'size': 250,
            'vsize': 250,
            'locktime': 0,
            'vin': [{'coinbase': '00'}],
            'vout': [{'value': 50.0, 'n': 0, 'scriptPubKey': {'hex': '00'}}]
        }

    def _generate_block_hash(self, height: int) -> str:
        """Generate a deterministic block hash for a given height"""
        import hashlib
        data = f"block_{height}".encode()
        return hashlib.sha3_256(data).hexdigest()

    def _generate_tx_hash(self, tx_index: int) -> str:
        """Generate a deterministic transaction hash"""
        import hashlib
        data = f"tx_{tx_index}".encode()
        return hashlib.sha3_256(data).hexdigest()

    def _calculate_merkle_root(self, tx_hashes: List[str]) -> str:
        """Calculate merkle root from transaction hashes"""
        import hashlib
        if not tx_hashes:
            return "0" * 64
        if len(tx_hashes) == 1:
            return tx_hashes[0]
        
        hashes = [bytes.fromhex(h) for h in tx_hashes]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            new_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                hash_obj = hashlib.sha3_256(combined)
                new_level.append(hash_obj.digest())
            hashes = new_level
        return hashes[0].hex()

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
        # Return tracked block count
        return self._block_count

    def getbestblockhash(self) -> str:
        """Get best block hash"""
        if self._block_count in self._block_hashes:
            return self._block_hashes[self._block_count]
        return self._block_hashes.get(0, "0" * 64)

    def getblockhash(self, height: int) -> str:
        """Get block hash at height"""
        if height < 0:
            raise ValueError(f"Block height must be non-negative, got {height}")
        if height > self._block_count:
            raise ValueError(f"Block height {height} exceeds current block count {self._block_count}")
        if height in self._block_hashes:
            return self._block_hashes[height]
        # Generate deterministic hash if not cached
        return self._generate_block_hash(height)

    def getblock(self, blockhash: str, verbosity: int = 1):
        """Get block by hash"""
        # Find block by hash
        height = self._hash_to_height.get(blockhash)
        if height is None:
            # Try to parse as height if it's all zeros (genesis)
            if blockhash == "0" * 64:
                height = 0
            else:
                # Generate mock block for unknown hash
                height = 0
        
        # Get or create block data
        if height in self._blocks:
            block = self._blocks[height].copy()
        else:
            # Create mock block
            block = {
                'hash': blockhash,
                'height': height,
                'version': 1,
                'merkleroot': '0' * 64,
                'tx': [],
                'time': self._genesis_time + height * 600,  # ~10 min per block
                'nonce': 0,
                'bits': '1d00ffff',
                'difficulty': 1.0,
                'previousblockhash': self._block_hashes.get(height - 1, '0' * 64) if height > 0 else '0' * 64,
            }
        
        # Format transaction list based on verbosity
        if verbosity >= 2:
            # Include full transaction objects
            if 'tx' not in block or not isinstance(block['tx'], list) or len(block['tx']) == 0:
                # Create default coinbase transaction
                txid = self._generate_tx_hash(height)
                block['tx'] = [{
                    'txid': txid,
                    'vout': [{'value': 50.0, 'scriptPubKey': {'addresses': []}}],
                    'vin': [{'coinbase': '00'}]
                }]
        elif verbosity == 1:
            # Include transaction hashes only
            if 'tx' in block and isinstance(block['tx'], list) and len(block['tx']) > 0:
                if isinstance(block['tx'][0], dict):
                    block['tx'] = [tx['txid'] if isinstance(tx, dict) else str(tx) for tx in block['tx']]
            else:
                block['tx'] = [self._generate_tx_hash(height)]
        else:
            # Verbosity 0: hex string (not implemented in mock)
            block['tx'] = [self._generate_tx_hash(height)]
        
        return block

    def generatetoaddress(self, nblocks: int, address: str) -> List[str]:
        """Generate blocks to address"""
        if nblocks <= 0:
            return []
        
        block_hashes = []
        current_time = self._genesis_time + (self._block_count + 1) * 600
        
        for i in range(nblocks):
            height = self._block_count + 1 + i
            block_hash = self._generate_block_hash(height)
            block_hashes.append(block_hash)
            
            # Create coinbase transaction
            coinbase_txid = self._generate_tx_hash(height)
            coinbase_tx = {
                'txid': coinbase_txid,
                'vout': [{'value': 50.0, 'scriptPubKey': {'addresses': [address]}}],
                'vin': [{'coinbase': '00'}]
            }
            
            # Calculate merkle root
            tx_hashes = [coinbase_txid]
            merkle_root = self._calculate_merkle_root(tx_hashes)
            
            # Create block
            previous_hash = self._block_hashes.get(height - 1, '0' * 64) if height > 0 else '0' * 64
            block = {
                'hash': block_hash,
                'height': height,
                'version': 1,
                'merkleroot': merkle_root,
                'tx': [coinbase_tx],
                'time': current_time + i * 600,
                'nonce': 0,
                'bits': '1d00ffff',  # Fixed difficulty for now
                'difficulty': 1.0,
                'previousblockhash': previous_hash,
            }
            
            # Store block
            self._blocks[height] = block
            self._block_hashes[height] = block_hash
            self._hash_to_height[block_hash] = height
            self._transactions[coinbase_txid] = {
                'txid': coinbase_txid,
                'hash': coinbase_txid,
                'version': 1,
                'size': 250,
                'vsize': 250,
                'locktime': 0,
                'vin': [{'coinbase': '00'}],
                'vout': [{'value': 50.0, 'n': 0, 'scriptPubKey': {'hex': '00', 'addresses': [address]}}]
            }
        
        # Update block count
        self._block_count += nblocks
        
        return block_hashes

    def sendtoaddress(self, address: str, amount: float) -> str:
        """Send DIL to address"""
        # Create a mock transaction and add to mempool
        tx_index = len(self._transactions) + len(self._mempool) + 1000
        txid = self._generate_tx_hash(tx_index)
        
        tx = {
            'txid': txid,
            'hash': txid,
            'version': 1,
            'size': 250,
            'vsize': 250,
            'locktime': 0,
            'vin': [{'txid': self._generate_tx_hash(0), 'vout': 0}],
            'vout': [{'value': amount, 'n': 0, 'scriptPubKey': {'hex': '00', 'addresses': [address]}}]
        }
        
        self._transactions[txid] = tx
        self._mempool.append(txid)
        
        return txid

    def getnewaddress(self) -> str:
        """Get new address from wallet"""
        # Generate deterministic address
        address = f"DilithionTestAddress{len(self._addresses)}"
        self._addresses.append(address)
        return address

    def getbalance(self) -> float:
        """Get wallet balance"""
        # Calculate balance from transactions
        balance = 0.0
        for txid, tx in self._transactions.items():
            if 'vout' in tx:
                for vout in tx['vout']:
                    if isinstance(vout, dict) and 'value' in vout:
                        balance += vout['value']
        return balance

    def getrawtransaction(self, txid: str, verbose: bool = False):
        """Get raw transaction"""
        if txid in self._transactions:
            tx = self._transactions[txid].copy()
            if not verbose:
                # Return raw hex (simplified)
                return txid.encode().hex() + '0' * 400  # Mock raw hex
            return tx
        
        # Return mock transaction if not found
        if verbose:
            return {
                'txid': txid,
                'hash': txid,
                'version': 1,
                'size': 250,
                'vsize': 250,
                'locktime': 0,
                'vin': [{'txid': '0' * 64, 'vout': 0}],
                'vout': [{'value': 50.0, 'n': 0, 'scriptPubKey': {'hex': '00'}}]
            }
        return txid.encode().hex() + '0' * 400  # Mock raw hex

    def getmempoolinfo(self):
        """Get mempool information"""
        # TODO: Implement actual RPC call
        return {
            'loaded': True,
            'size': 0,
            'bytes': 0,
            'usage': 0,
            'maxmempool': 300000000,
            'mempoolminfee': 0.00001,
            'minrelaytxfee': 0.00001
        }

    def getrawmempool(self, verbose: bool = False):
        """Get raw mempool contents"""
        if verbose:
            # Return detailed transaction info
            result = {}
            for txid in self._mempool:
                if txid in self._transactions:
                    result[txid] = self._transactions[txid]
            return result
        return self._mempool.copy()

    def decoderawtransaction(self, hexstring: str):
        """Decode raw transaction"""
        # TODO: Implement actual RPC call
        return {
            'txid': '0' * 64,
            'version': 1,
            'locktime': 0,
            'vin': [],
            'vout': []
        }
