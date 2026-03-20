#!/usr/bin/env python3
"""
Dilithion Bridge Relayer
========================
Monitors DIL and DilV chains for deposits to bridge addresses,
mints wrapped tokens (wDIL/wDILV) on Base, and processes burn
events to send native coins back.

TRUST MODEL: This is a custodial bridge. The operator (this relayer)
controls minting on Base and holds native coins at bridge addresses.

Usage:
    python relayer.py [--dry-run]
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

import config
from dilithion_rpc import DilithionRPC
from state_db import StateDB

logger = logging.getLogger("relayer")

# ── Contract ABI (mint + burn events only — minimal) ─────────────────

WRAPPED_TOKEN_ABI = json.loads("""[
    {
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "nativeTxId", "type": "bytes32"}
        ],
        "name": "mint",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "", "type": "bytes32"}],
        "name": "minted",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": false,
        "inputs": [
            {"indexed": true,  "name": "to",         "type": "address"},
            {"indexed": false, "name": "amount",      "type": "uint256"},
            {"indexed": true,  "name": "nativeTxId",  "type": "bytes32"}
        ],
        "name": "BridgeMint",
        "type": "event"
    },
    {
        "anonymous": false,
        "inputs": [
            {"indexed": true,  "name": "from",          "type": "address"},
            {"indexed": false, "name": "amount",         "type": "uint256"},
            {"indexed": false, "name": "nativeAddress",  "type": "string"}
        ],
        "name": "BridgeBurn",
        "type": "event"
    }
]""")


class BridgeRelayer:
    """Main bridge relayer — polls chains and processes deposits/withdrawals."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

        # Native chain RPC clients
        self.dil_rpc = DilithionRPC(
            config.DIL_RPC_URL, config.RPC_USER, config.RPC_PASSWORD, "dil"
        )
        self.dilv_rpc = DilithionRPC(
            config.DILV_RPC_URL, config.RPC_USER, config.RPC_PASSWORD, "dilv"
        )

        # Base (Ethereum L2) connection
        self.w3 = Web3(Web3.HTTPProvider(config.BASE_RPC_URL))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if config.BRIDGE_PRIVATE_KEY:
            self.account = self.w3.eth.account.from_key(config.BRIDGE_PRIVATE_KEY)
        else:
            self.account = None
            logger.warning("No BRIDGE_PRIVATE_KEY set — minting disabled")

        # Contracts
        self.wdil_contract = None
        self.wdilv_contract = None
        if config.WDIL_CONTRACT:
            self.wdil_contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(config.WDIL_CONTRACT),
                abi=WRAPPED_TOKEN_ABI,
            )
        if config.WDILV_CONTRACT:
            self.wdilv_contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(config.WDILV_CONTRACT),
                abi=WRAPPED_TOKEN_ABI,
            )

        # State DB
        self.db = StateDB(
            os.path.join(os.path.dirname(__file__), "bridge_state.db")
        )

        # Retired bridge addresses to watch for misdirected deposits
        self.retired_addresses = {
            "dil":  config.RETIRED_DIL_BRIDGE_ADDRESSES,
            "dilv": config.RETIRED_DILV_BRIDGE_ADDRESSES,
        }

        # Chain config mapping
        self.chain_config = {
            "dil": {
                "rpc": self.dil_rpc,
                "bridge_address": config.DIL_BRIDGE_ADDRESS,
                "confirmations": config.DIL_CONFIRMATIONS,
                "contract": self.wdil_contract,
                "daily_cap": config.DAILY_MINT_CAP_DIL,
                "max_per_deposit": config.MAX_PER_DEPOSIT_DIL,
                "unit": "ions",
                "coin": "DIL",
                "start_height": config.DIL_BRIDGE_START_HEIGHT,
            },
            "dilv": {
                "rpc": self.dilv_rpc,
                "bridge_address": config.DILV_BRIDGE_ADDRESS,
                "confirmations": config.DILV_CONFIRMATIONS,
                "contract": self.wdilv_contract,
                "daily_cap": config.DAILY_MINT_CAP_DILV,
                "max_per_deposit": config.MAX_PER_DEPOSIT_DILV,
                "unit": "volts",
                "coin": "DilV",
                "start_height": config.DILV_BRIDGE_START_HEIGHT,
            },
        }

    # ── Main loop ────────────────────────────────────────────────────

    def run(self):
        """Main polling loop."""
        logger.info("Bridge relayer starting...")
        logger.info(f"  Network:  {config.NETWORK.upper()}")
        logger.info(f"  DIL RPC:  {config.DIL_RPC_URL}")
        logger.info(f"  DilV RPC: {config.DILV_RPC_URL}")
        logger.info(f"  Base RPC: {config.BASE_RPC_URL}")
        logger.info(f"  Dry run:  {self.dry_run}")
        if config.NETWORK == "mainnet" and "sepolia" in config.BASE_RPC_URL:
            logger.error("NETWORK=mainnet but BASE_RPC_URL points to Sepolia! Aborting.")
            return

        self._check_connections()

        while True:
            try:
                for chain in ("dil", "dilv"):
                    self._check_reorgs(chain)
                    self._scan_deposits(chain)

                self._update_confirmations()
                self._process_confirmed_deposits()
                self._process_refunds()

                self._scan_base_burns()
                self._update_withdrawal_confirmations()
                self._process_confirmed_withdrawals()

                self._log_health()

            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Relayer loop error: {e}", exc_info=True)

            time.sleep(config.POLL_INTERVAL_SECONDS)

        self.db.close()

    # ── Connection check ─────────────────────────────────────────────

    def _check_connections(self):
        """Verify connectivity to all chains on startup."""
        for chain, cfg in self.chain_config.items():
            try:
                info = cfg["rpc"].get_blockchain_info()
                logger.info(
                    f"  [{chain}] Connected — height {info.get('blocks', '?')}, "
                    f"chain {info.get('chain', '?')}"
                )
            except Exception as e:
                logger.warning(f"  [{chain}] Not connected: {e}")

        try:
            base_block = self.w3.eth.block_number
            logger.info(f"  [base] Connected — block {base_block}")
        except Exception as e:
            logger.warning(f"  [base] Not connected: {e}")

    # ── Reorg detection ──────────────────────────────────────────────

    def _check_reorgs(self, chain: str):
        """Detect chain reorgs and mark affected deposits."""
        rpc = self.chain_config[chain]["rpc"]
        sync = self.db.get_sync_state(chain)
        if not sync:
            return

        stored_height, stored_hash = sync
        try:
            current_hash = rpc.get_block_hash(stored_height)
        except Exception:
            return  # Can't reach node, skip

        if current_hash == stored_hash:
            return  # No reorg

        logger.warning(
            f"[{chain}] REORG DETECTED at height {stored_height}! "
            f"Expected {stored_hash[:16]}..., got {current_hash[:16]}..."
        )

        # Walk back to find the fork point
        fork_height = stored_height
        while fork_height > 0:
            fork_height -= 1
            try:
                chain_hash = rpc.get_block_hash(fork_height)
            except Exception:
                break

            # Check if we have a record for this height
            # For simplicity, just roll back to fork_height
            # A more precise approach would check our DB for matching hashes
            break

        reorged_count = self.db.mark_deposits_reorged(chain, fork_height)
        logger.warning(
            f"[{chain}] Marked {reorged_count} deposits as reorged "
            f"(from height {fork_height})"
        )

        # Reset sync state to fork point
        try:
            fork_hash = rpc.get_block_hash(fork_height)
            self.db.set_sync_state(chain, fork_height, fork_hash)
        except Exception as e:
            logger.error(f"[{chain}] Failed to reset sync state: {e}")

    # ── Deposit scanning ─────────────────────────────────────────────

    def _scan_deposits(self, chain: str):
        """Scan native chain for new deposits to bridge address."""
        cfg = self.chain_config[chain]
        rpc = cfg["rpc"]
        bridge_addr = cfg["bridge_address"]

        if not bridge_addr:
            return  # Bridge address not configured

        try:
            current_height = rpc.get_block_count()
        except Exception as e:
            logger.debug(f"[{chain}] Can't get block count: {e}")
            return

        # Get starting height
        # If we have sync state, resume from where we left off.
        # If no sync state (fresh DB or reset), start from the bridge start
        # height — NOT current_height - 100 which would skip deposits.
        sync = self.db.get_sync_state(chain)
        bridge_start = self.chain_config[chain].get("start_height", 0)
        start_height = (sync[0] + 1) if sync else max(bridge_start, 0)

        if start_height > current_height:
            return  # Already up to date

        # Scan blocks (verbosity=2 gives full tx details in one RPC call)
        for height in range(start_height, current_height + 1):
            try:
                block_hash = rpc.get_block_hash(height)
                block = rpc.get_block(block_hash, verbosity=2)
            except Exception as e:
                logger.debug(f"[{chain}] Error fetching block {height}: {e}")
                break

            # With verbosity=2, tx is a list of full transaction dicts
            transactions = block.get("tx", [])
            for tx in transactions:
                if isinstance(tx, str):
                    # Fallback: verbosity=1 returns txid strings
                    self._check_tx_for_deposit_by_id(
                        chain, tx, height, block_hash, rpc, bridge_addr
                    )
                elif isinstance(tx, dict):
                    txid = tx.get("txid", "")
                    self._check_tx_for_deposit(
                        chain, txid, tx, height, block_hash, bridge_addr
                    )
                    self._check_tx_for_retired_deposit(chain, txid, tx, height)

            self.db.set_sync_state(chain, height, block_hash)

    def _check_tx_for_deposit_by_id(self, chain, txid, height, block_hash, rpc, bridge_addr):
        """Fetch tx by ID and check for deposit (fallback for verbosity=1)."""
        try:
            tx = rpc.get_raw_transaction(txid)
        except Exception:
            return
        self._check_tx_for_deposit(chain, txid, tx, height, block_hash, bridge_addr)

    def _check_tx_for_deposit(self, chain, txid, tx, height, block_hash, bridge_addr):
        """Check if a transaction contains a deposit to the bridge address.

        Handles Dilithion's vout format:
          - "address": "D..." (direct field, not nested under scriptPubKey)
          - "value": integer in satoshis (not float coins)
          - "scriptPubKey": hex string (not object)
        """
        vouts = tx.get("vout", [])
        deposit_vout = None
        deposit_amount = 0
        base_address = None

        # Find payment to bridge address
        for vout in vouts:
            # Dilithion format: address is a direct field
            addr = vout.get("address", "")
            # Also check Bitcoin Core format (scriptPubKey.addresses)
            if not addr:
                addresses = vout.get("scriptPubKey", {})
                if isinstance(addresses, dict):
                    for a in addresses.get("addresses", []):
                        if a == bridge_addr:
                            addr = a
                            break

            if addr == bridge_addr:
                deposit_vout = vout.get("n", 0)
                # Value could be satoshis (int) or coins (float)
                value = vout.get("value", 0)
                if isinstance(value, float) and value < 1000000:
                    deposit_amount = int(round(value * 1e8))
                else:
                    deposit_amount = int(value)

        if deposit_vout is None:
            return  # No payment to bridge address

        # Find OP_RETURN with bridge metadata
        for vout in vouts:
            # Dilithion format: scriptPubKey is hex string
            spk = vout.get("scriptPubKey", "")
            if isinstance(spk, str):
                spk_hex = spk
            elif isinstance(spk, dict):
                spk_hex = spk.get("hex", "")
            else:
                continue
            base_address = self._parse_bridge_op_return(spk_hex)
            if base_address:
                break

        if not base_address:
            logger.warning(
                f"[{chain}] Deposit {txid} to bridge has NO valid OP_RETURN! "
                f"Amount: {deposit_amount}. Manual recovery needed."
            )
            return

        # Extract sender address from vin (first input's previous output)
        sender_address = self._get_sender_address(chain, tx)

        # Validate per-deposit limit (relayer-side)
        max_deposit = self.chain_config[chain]["max_per_deposit"]
        if deposit_amount > max_deposit:
            coin = self.chain_config[chain]["coin"]
            logger.warning(
                f"[{chain}] Deposit {txid} exceeds per-deposit limit: "
                f"{deposit_amount / 1e8:.2f} > {max_deposit / 1e8:.2f} {coin}. "
                f"Sender: {sender_address or 'unknown'}. Queuing for auto-refund."
            )
            # Record in DB as over_limit so the refund loop picks it up
            self.db.insert_deposit(
                chain, txid, deposit_vout, deposit_amount,
                base_address, height, block_hash, sender_address
            )
            # Immediately mark as over_limit (not pending)
            row = self.db.conn.execute(
                "SELECT id FROM deposits WHERE native_txid = ? AND native_vout = ?",
                (txid, deposit_vout)
            ).fetchone()
            if row:
                self.db.conn.execute(
                    "UPDATE deposits SET status = 'over_limit' WHERE id = ?",
                    (row["id"],)
                )
                self.db.conn.commit()
            return

        # Insert into DB (idempotent — UNIQUE constraint handles duplicates)
        inserted = self.db.insert_deposit(
            chain, txid, deposit_vout, deposit_amount,
            base_address, height, block_hash, sender_address
        )
        if inserted:
            coin = self.chain_config[chain]["coin"]
            logger.info(
                f"[{chain}] New deposit: {deposit_amount / 1e8:.8f} {coin} "
                f"-> {base_address} (tx: {txid[:16]}... height: {height})"
            )

    def _check_tx_for_retired_deposit(self, chain: str, txid: str, tx: dict, height: int):
        """Alert if a deposit was sent to a retired (old) bridge address.

        These funds cannot be processed automatically — the operator must
        manually mint wTokens for the affected user.
        """
        retired = self.retired_addresses.get(chain, [])
        if not retired:
            return

        vouts = tx.get("vout", [])
        for vout in vouts:
            addr = vout.get("address", "")
            if addr not in retired:
                continue

            # Found a payment to a retired address — extract amount and OP_RETURN
            value = vout.get("value", 0)
            amount = int(round(value * 1e8)) if isinstance(value, float) and value < 1e9 else int(value)
            coin = self.chain_config[chain]["coin"]

            # Try to parse the OP_RETURN for the destination Base address
            base_address = None
            for v in vouts:
                spk = v.get("scriptPubKey", "")
                spk_hex = spk if isinstance(spk, str) else spk.get("hex", "")
                base_address = self._parse_bridge_op_return(spk_hex)
                if base_address:
                    break

            logger.error(
                f"[{chain}] *** RETIRED ADDRESS DEPOSIT DETECTED ***\n"
                f"  TxID:         {txid}\n"
                f"  Amount:       {amount / 1e8:.8f} {coin}\n"
                f"  Sent to:      {addr}  (RETIRED — funds unrecoverable by relayer)\n"
                f"  Base address: {base_address or 'NOT FOUND — check OP_RETURN manually'}\n"
                f"  Height:       {height}\n"
                f"  ACTION:       Manually call mint() on the w{coin} contract to make user whole."
            )

    def _parse_bridge_op_return(self, spk_hex: str) -> str | None:
        """
        Parse OP_RETURN output for bridge metadata.
        Expected format: 6a 19 44425247 <20-byte-address>
          - 6a = OP_RETURN
          - 19 = push 25 bytes (0x19 = 25 decimal: 4 tag + 20 address + 1 checksum? No, just 24)
          - Actually: 6a 18 44425247 <20-byte-address>
            6a = OP_RETURN, 18 = push 24 bytes (4 tag + 20 address)

        Returns checksummed Base address or None.
        """
        if not spk_hex:
            return None

        try:
            data = bytes.fromhex(spk_hex)
        except ValueError:
            return None

        # Must start with OP_RETURN (0x6a)
        if len(data) < 2 or data[0] != 0x6a:
            return None

        # Next byte is push length
        push_len = data[1]
        payload = data[2:]

        if len(payload) != push_len:
            return None

        # Expected payload: 4 bytes tag + 20 bytes address = 24 bytes
        if push_len != 24:
            return None

        tag = payload[:4]
        if tag != config.BRIDGE_TAG:
            return None

        addr_bytes = payload[4:24]

        # Validate non-zero address
        if addr_bytes == b'\x00' * 20:
            logger.warning("Bridge OP_RETURN has zero address — rejecting")
            return None

        return Web3.to_checksum_address("0x" + addr_bytes.hex())

    def _get_sender_address(self, chain: str, tx: dict) -> str | None:
        """Extract sender address from the transaction's change output.

        Since getrawtransaction isn't implemented, we can't look up the
        previous TX's output. Instead, use the change output heuristic:
        the non-bridge, non-OP_RETURN output is the sender's change address.
        """
        bridge_addr = self.chain_config[chain]["bridge_address"]
        vouts = tx.get("vout", [])

        for vout in vouts:
            addr = vout.get("address", "")
            if not addr:
                continue
            # Skip the bridge deposit output and OP_RETURN (no address)
            if addr == bridge_addr:
                continue
            # This is the change output — the sender's address
            return addr

        return None

    def _process_refunds(self):
        """Auto-refund deposits that exceed per-deposit limits.

        Sends coins back to the sender minus a small fee for the return tx.
        """
        refunds = self.db.get_pending_refunds()
        if not refunds:
            return

        REFUND_FEE = 10000  # 0.0001 coins fee deducted from refund (covers tx fee)

        for dep in refunds:
            chain = dep["chain"]
            sender = dep["sender_address"]
            amount = dep["amount"]
            coin = self.chain_config[chain]["coin"]

            if not sender:
                logger.warning(
                    f"[{chain}] Cannot refund deposit {dep['native_txid'][:16]}... "
                    f"— sender address unknown. Manual refund needed."
                )
                # Use 'refund_failed' status so it doesn't enter the mint retry loop
                self.db.conn.execute(
                    """UPDATE deposits SET status = 'refund_failed', error_msg = ?,
                       updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                    ("No sender address for auto-refund", dep["id"])
                )
                self.db.conn.commit()
                continue

            refund_amount = amount - REFUND_FEE
            if refund_amount <= 0:
                logger.warning(
                    f"[{chain}] Deposit {dep['native_txid'][:16]}... too small to refund "
                    f"after fee. Amount: {amount}"
                )
                self.db.mark_deposit_failed(dep["id"], "Too small to refund after fee")
                continue

            try:
                rpc = self.chain_config[chain]["rpc"]
                # sendtoaddress expects coins (float), not ions/volts
                refund_coins = refund_amount / 1e8
                refund_txid = rpc.send_to_address(sender, refund_coins)
                logger.info(
                    f"[{chain}] AUTO-REFUND: {refund_amount / 1e8:.8f} {coin} "
                    f"back to {sender} (tx: {refund_txid[:16]}...)"
                )
                self.db.mark_deposit_refunded(dep["id"], refund_txid)
            except Exception as e:
                logger.error(
                    f"[{chain}] Refund failed for {dep['native_txid'][:16]}...: {e}"
                )
                # Use refund_failed so it doesn't enter the mint retry loop
                self.db.conn.execute(
                    """UPDATE deposits SET status = 'refund_failed', error_msg = ?,
                       retry_count = COALESCE(retry_count, 0) + 1,
                       updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                    (f"Refund failed: {e}", dep["id"])
                )
                self.db.conn.commit()

    # ── Confirmation updates ─────────────────────────────────────────

    def _update_confirmations(self):
        """Update confirmation counts for pending deposits."""
        for chain in ("dil", "dilv"):
            rpc = self.chain_config[chain]["rpc"]
            required = self.chain_config[chain]["confirmations"]

            try:
                current_height = rpc.get_block_count()
            except Exception:
                continue

            for dep in self.db.get_pending_deposits(chain):
                confs = current_height - dep["block_height"] + 1
                if confs >= required:
                    self.db.confirm_deposit(dep["id"], confs)
                    logger.info(
                        f"[{chain}] Deposit {dep['native_txid'][:16]}... "
                        f"confirmed ({confs} confs)"
                    )
                else:
                    self.db.update_deposit_confirmations(dep["id"], confs)

    # ── Mint processing ──────────────────────────────────────────────

    def _process_confirmed_deposits(self):
        """Mint wTokens for deposits with enough confirmations."""
        if not self.account:
            return  # No private key configured

        # Process confirmed deposits + retryable failed deposits
        deposits = list(self.db.get_confirmed_deposits())
        retryable = list(self.db.get_retryable_deposits())
        if retryable:
            logger.info(f"Retrying {len(retryable)} previously failed deposits")
            deposits.extend(retryable)

        for dep in deposits:
            chain = dep["chain"]
            cfg = self.chain_config[chain]
            contract = cfg["contract"]

            if not contract:
                logger.warning(f"[{chain}] No contract configured — skipping mint")
                continue

            # Convert txid to bytes32 for contract
            native_txid_bytes = bytes.fromhex(dep["native_txid"])
            if len(native_txid_bytes) != 32:
                native_txid_bytes = native_txid_bytes[:32].ljust(32, b'\x00')

            # Check contract-side replay protection (belt + suspenders)
            try:
                already_minted = contract.functions.minted(native_txid_bytes).call()
                if already_minted:
                    logger.warning(
                        f"[{chain}] Contract says already minted for "
                        f"{dep['native_txid'][:16]}... — marking as minted"
                    )
                    self.db.mark_deposit_minted(dep["id"], "already-on-chain")
                    continue
            except Exception as e:
                logger.error(f"[{chain}] Error checking minted status: {e}")
                continue

            if self.dry_run:
                logger.info(
                    f"[{chain}] DRY RUN: Would mint {dep['amount'] / 1e8:.8f} "
                    f"{cfg['coin']} to {dep['base_address']}"
                )
                continue

            # Build and send mint transaction
            try:
                tx = contract.functions.mint(
                    Web3.to_checksum_address(dep["base_address"]),
                    dep["amount"],
                    native_txid_bytes,
                ).build_transaction({
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
                    "gas": 150_000,
                    "maxFeePerGas": self.w3.eth.gas_price * 2,
                    "maxPriorityFeePerGas": self.w3.to_wei(0.001, "gwei"),
                })

                signed = self.account.sign_transaction(tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

                if receipt.status == 1:
                    mint_txid = tx_hash.hex()
                    self.db.mark_deposit_minted(dep["id"], mint_txid)
                    self.db.add_daily_minted(chain, dep["amount"])
                    logger.info(
                        f"[{chain}] Minted {dep['amount'] / 1e8:.8f} {cfg['coin']} "
                        f"to {dep['base_address']} (tx: {mint_txid[:16]}...)"
                    )
                else:
                    self.db.mark_deposit_failed(dep["id"], "Mint tx reverted")
                    logger.error(
                        f"[{chain}] Mint tx reverted for deposit "
                        f"{dep['native_txid'][:16]}..."
                    )

            except Exception as e:
                self.db.mark_deposit_failed(dep["id"], str(e))
                logger.error(
                    f"[{chain}] Mint failed for {dep['native_txid'][:16]}...: {e}"
                )

            # Rate-limit between mints to avoid nonce collisions and Base RPC 429s
            if len(deposits) > 1:
                time.sleep(3)

    # ── Burn scanning (Base → native) ────────────────────────────────

    def _scan_base_burns(self):
        """Monitor BridgeBurn events on Base for both contracts."""
        sync = self.db.get_sync_state("base")
        try:
            current_block = self.w3.eth.block_number
        except Exception as e:
            logger.debug(f"[base] Can't get block number: {e}")
            return

        start_block = (sync[0] + 1) if sync else max(0, current_block - 1000)
        if start_block > current_block:
            return

        for chain, cfg in self.chain_config.items():
            contract = cfg["contract"]
            if not contract:
                continue

            try:
                # web3 v7: use get_logs() instead of create_filter()
                events = contract.events.BridgeBurn().get_logs(
                    from_block=start_block,
                    to_block=current_block,
                )
            except Exception as e:
                logger.debug(f"[base/{chain}] Error fetching burn events: {e}")
                continue

            for event in events:
                amount = event.args.amount
                native_address = event.args.nativeAddress
                burn_txid = event.transactionHash.hex()
                log_index = event.logIndex
                block_num = event.blockNumber

                inserted = self.db.insert_withdrawal(
                    chain, burn_txid, log_index, block_num, amount, native_address
                )
                if inserted:
                    logger.info(
                        f"[base/{chain}] New burn: {amount / 1e8:.8f} {cfg['coin']} "
                        f"-> {native_address} (tx: {burn_txid[:16]}...)"
                    )

        # Update Base sync state
        try:
            block_hash = self.w3.eth.get_block(current_block).hash.hex()
            self.db.set_sync_state("base", current_block, block_hash)
        except Exception:
            pass

    def _update_withdrawal_confirmations(self):
        """Check Base confirmations for pending withdrawals."""
        try:
            current_block = self.w3.eth.block_number
        except Exception:
            return

        for w in self.db.get_pending_withdrawals():
            confs = current_block - w["burn_block_number"]
            if confs >= config.BASE_CONFIRMATIONS:
                self.db.confirm_withdrawal(w["id"])
                logger.info(
                    f"[base] Withdrawal {w['burn_txid'][:16]}... "
                    f"confirmed ({confs} Base blocks)"
                )

    # ── Native coin withdrawal ───────────────────────────────────────

    def _process_confirmed_withdrawals(self):
        """Send native coins for confirmed burn events."""
        for w in self.db.get_confirmed_withdrawals():
            chain = w["chain"]
            rpc = self.chain_config[chain]["rpc"]
            coin = self.chain_config[chain]["coin"]
            amount_coins = w["amount"] / 1e8

            if self.dry_run:
                logger.info(
                    f"[{chain}] DRY RUN: Would send {amount_coins:.8f} {coin} "
                    f"to {w['native_address']}"
                )
                continue

            try:
                native_txid = rpc.send_to_address(w["native_address"], amount_coins)
                self.db.mark_withdrawal_sent(w["id"], native_txid)
                logger.info(
                    f"[{chain}] Sent {amount_coins:.8f} {coin} "
                    f"to {w['native_address']} (tx: {native_txid[:16]}...)"
                )
            except Exception as e:
                self.db.mark_withdrawal_failed(w["id"], str(e))
                logger.error(
                    f"[{chain}] Withdrawal send failed: {e}"
                )

    # ── Health logging ───────────────────────────────────────────────

    def _log_health(self):
        """Log operational metrics every cycle."""
        stats = self.db.get_stats()

        # Check gas balance
        gas_str = ""
        if self.account:
            try:
                balance_wei = self.w3.eth.get_balance(self.account.address)
                balance_eth = float(self.w3.from_wei(balance_wei, "ether"))
                gas_str = f" | gas: {balance_eth:.4f} ETH"
                if balance_eth < config.GAS_ALERT_THRESHOLD_ETH:
                    logger.warning(
                        f"LOW GAS: Base ETH balance is {balance_eth:.6f} ETH "
                        f"(threshold: {config.GAS_ALERT_THRESHOLD_ETH})"
                    )
            except Exception:
                pass

        # Check daily mint vs cap
        for chain in ("dil", "dilv"):
            daily = stats.get(f"daily_minted_{chain}", 0)
            cap = self.chain_config[chain]["daily_cap"]
            if cap > 0 and daily > cap * 0.8:
                logger.warning(
                    f"[{chain}] Daily mint at {daily / cap * 100:.0f}% of cap "
                    f"({daily / 1e8:.2f} / {cap / 1e8:.2f})"
                )

        pending_deps = stats.get("deposits_pending", 0) + stats.get("deposits_confirmed", 0)
        pending_wdrs = stats.get("withdrawals_pending", 0) + stats.get("withdrawals_confirmed", 0)
        minted = stats.get("deposits_minted", 0)
        cap_deferred = stats.get("deposits_cap_deferred", 0)

        # Show deferred deposits waiting for cap reset
        deferred_str = f" | deferred: {cap_deferred}" if cap_deferred > 0 else ""

        # Always log status so the operator knows the relayer is alive
        logger.info(
            f"Pending: {pending_deps} deposits, {pending_wdrs} withdrawals "
            f"| minted: {minted}{deferred_str}{gas_str}"
        )


# ── Entry point ──────────────────────────────────────────────────────

def setup_logging():
    """Configure logging with unbuffered output for reliable background operation."""
    # Force unbuffered stdout on Windows (prevents "stall" appearance)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    # Flush after every log message
    stream_handler.flush = sys.stdout.flush

    handlers = [stream_handler]
    if config.LOG_FILE:
        handlers.append(logging.FileHandler(config.LOG_FILE))

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        handlers=handlers,
    )


def main():
    parser = argparse.ArgumentParser(description="Dilithion Bridge Relayer")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Monitor chains but don't mint or send (for testing)"
    )
    args = parser.parse_args()

    setup_logging()

    relayer = BridgeRelayer(dry_run=args.dry_run)
    relayer.run()


if __name__ == "__main__":
    main()
