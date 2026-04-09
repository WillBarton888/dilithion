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
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
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

        # Bridge pause state — set by auto-pause on invariant breach
        self.paused = False
        self.pause_reason = ""

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

        # Reconcile any incomplete sends from a prior crash
        self._reconcile_incomplete_sends()
        self._reconcile_incomplete_refunds()

        loop_count = 0

        while True:
            try:
                if self.paused:
                    logger.warning(
                        f"BRIDGE PAUSED — skipping all processing. "
                        f"Reason: {self.pause_reason}"
                    )
                    time.sleep(config.POLL_INTERVAL_SECONDS)
                    continue

                for chain in ("dil", "dilv"):
                    self._check_reorgs(chain)
                    if self.paused:
                        break  # Reorg check may have triggered pause
                    self._scan_deposits(chain)

                if not self.paused:
                    self._update_confirmations()
                    self._process_confirmed_deposits()
                    self._process_refunds()

                    self._scan_base_burns()
                    self._update_withdrawal_confirmations()
                    self._process_confirmed_withdrawals()

                    self._check_backing_invariant()

                self._log_health()

                loop_count += 1

                # Periodic reconciliation every ~5 min (30 * 10s)
                # Resolves withdrawals/refunds stuck in 'sending'/'refunding'
                # from ambiguous RPC failures during normal operation.
                if loop_count % 30 == 0:
                    self._reconcile_incomplete_sends()
                    self._reconcile_incomplete_refunds()

                # Rescan wallets every hour (360 iterations * 10s interval)
                if loop_count % 360 == 0:
                    for chain in ("dil", "dilv"):
                        try:
                            self.chain_config[chain]["rpc"].rescan_wallet()
                            logger.info(f"[{chain}] Periodic wallet rescan complete")
                        except Exception as e:
                            logger.warning(f"[{chain}] Wallet rescan failed: {e}")

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

    # ── Bridge pause control ───────────────────────────────────────

    def _pause_bridge(self, reason: str):
        """Pause all bridge processing. Requires manual intervention to resume.

        This is a fail-safe for backing invariant breaches, catastrophic
        reorgs, or other conditions where continuing could lose funds.
        """
        self.paused = True
        self.pause_reason = reason
        logger.critical(
            f"BRIDGE PAUSED: {reason}. "
            f"Manual intervention required to resume."
        )

    # ── Reorg detection ──────────────────────────────────────────────

    def _check_reorgs(self, chain: str):
        """Detect chain reorgs and mark affected deposits."""
        rpc = self.chain_config[chain]["rpc"]
        sync = self.db.get_sync_state(chain)
        if not sync:
            return

        stored_height, stored_hash = sync
        try:
            current_height = rpc.get_block_count()
        except Exception:
            return  # Can't reach node, skip

        # Chain reset detection: stored height is far beyond actual chain tip.
        # Use a threshold of 100 blocks to avoid false positives from normal
        # 1-2 block race conditions during scanning.
        if stored_height > current_height + 100:
            bridge_start = self.chain_config[chain].get("start_height", 0)
            logger.warning(
                f"[{chain}] CHAIN RESET DETECTED: stored height {stored_height} > "
                f"chain height {current_height} (delta {stored_height - current_height}). "
                f"Resetting sync to {bridge_start}."
            )
            try:
                reset_hash = rpc.get_block_hash(bridge_start) if bridge_start <= current_height else ""
                self.db.set_sync_state(chain, bridge_start, reset_hash)
            except Exception as e:
                logger.error(f"[{chain}] Failed to reset sync after chain reset: {e}")
            return

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

        # Walk back to find the true fork point using stored block hashes.
        # Track WHY we exit the loop to distinguish "found fork point"
        # from "RPC error" from "exceeded max walkback".
        fork_height = stored_height
        max_walkback = 100  # safety bound — configurable
        walked = 0
        fork_found = False
        rpc_failed = False
        while fork_height > 0 and walked < max_walkback:
            fork_height -= 1
            walked += 1
            try:
                chain_hash = rpc.get_block_hash(fork_height)
            except Exception as e:
                logger.warning(
                    f"[{chain}] RPC failed during reorg walkback at height "
                    f"{fork_height}: {e}. Aborting walkback, will retry."
                )
                rpc_failed = True
                break
            stored_block_hash = self.db.get_block_hash(chain, fork_height)
            if stored_block_hash and chain_hash == stored_block_hash:
                # Found common ancestor — reorg starts one above
                fork_height += 1
                fork_found = True
                break

        # If RPC failed mid-walkback, don't mark anything reorged — we
        # don't know the true fork point. Retry next cycle.
        if rpc_failed:
            return

        if walked >= max_walkback and not fork_found:
            # Catastrophic reorg — auto-pause bridge
            logger.critical(
                f"[{chain}] CATASTROPHIC REORG: walkback exceeded {max_walkback} "
                f"blocks without finding common ancestor! AUTO-PAUSING BRIDGE."
            )
            self._pause_bridge(
                f"Catastrophic reorg on {chain}: >{max_walkback} blocks deep"
            )
            return

        # Check for backing invariant breach: were any reorged deposits
        # already minted (wTokens issued on Base)?  Only check deposits
        # within the actual reorg range (fork_height to stored_height),
        # not deposits from a prior chain era (e.g. pre-reset heights).
        all_above = self.db.get_minted_deposits_above_height(
            chain, fork_height
        )
        minted_at_risk = [
            dep for dep in all_above
            if dep['block_height'] <= stored_height
        ]
        if minted_at_risk:
            logger.critical(
                f"[{chain}] BACKING INVARIANT BREACH: {len(minted_at_risk)} "
                f"minted deposit(s) are in the reorged range (height >= {fork_height}). "
                f"wTokens are potentially unbacked! AUTO-PAUSING BRIDGE."
            )
            for dep in minted_at_risk:
                logger.critical(
                    f"  - Deposit {dep['id']}: {dep['amount'] / 1e8:.8f} "
                    f"at height {dep['block_height']}, mint_txid={dep['mint_txid']}"
                )
            self._pause_bridge(
                f"Backing invariant breach on {chain}: "
                f"{len(minted_at_risk)} minted deposits reorged"
            )

        reorged_count = self.db.mark_deposits_reorged(chain, fork_height)
        logger.warning(
            f"[{chain}] Marked {reorged_count} deposits as reorged "
            f"(from height {fork_height}, walked back {walked} blocks)"
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

        if start_height > current_height + 100:
            # Sync pointer is far ahead of actual chain — likely a chain reset.
            # Reset to bridge start height so we don't silently miss deposits.
            logger.warning(
                f"[{chain}] Sync height {start_height} > chain height {current_height} "
                f"(delta {start_height - current_height})! "
                f"Possible chain reset. Resetting scan to bridge start height {bridge_start}."
            )
            start_height = max(bridge_start, 0)
            if start_height > current_height:
                return  # Bridge start is still ahead (shouldn't happen)
        elif start_height > current_height:
            return  # Normal case: slightly ahead, just wait for next block

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
            self.db.store_block_hash(chain, height, block_hash)

        # Prune old block hashes periodically (keep last 200)
        self.db.prune_block_hashes(chain, keep_last=200)

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
        """Handle deposits sent to retired (old) bridge addresses.

        The native coins at retired addresses aren't directly spendable by the
        relayer, but since this is a custodial bridge and we control minting,
        we honor these deposits by recording and auto-minting for the user.
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
            deposit_vout = vout.get("n", 0)

            # Try to parse the OP_RETURN for the destination Base address
            base_address = None
            for v in vouts:
                spk = v.get("scriptPubKey", "")
                spk_hex = spk if isinstance(spk, str) else spk.get("hex", "")
                base_address = self._parse_bridge_op_return(spk_hex)
                if base_address:
                    break

            logger.warning(
                f"[{chain}] *** RETIRED ADDRESS DEPOSIT ***\n"
                f"  TxID:         {txid}\n"
                f"  Amount:       {amount / 1e8:.8f} {coin}\n"
                f"  Sent to:      {addr}  (RETIRED bridge address)\n"
                f"  Base address: {base_address or 'NOT FOUND'}\n"
                f"  Height:       {height}\n"
                f"  Auto-processing: recording deposit for minting."
            )

            if not base_address:
                logger.error(
                    f"[{chain}] Retired address deposit {txid} has NO valid OP_RETURN! "
                    f"Amount: {amount / 1e8:.8f} {coin}. Manual recovery needed."
                )
                continue

            # Validate per-deposit limit
            max_deposit = self.chain_config[chain]["max_per_deposit"]
            if amount > max_deposit:
                logger.warning(
                    f"[{chain}] Retired address deposit {txid} exceeds limit: "
                    f"{amount / 1e8:.2f} > {max_deposit / 1e8:.2f} {coin}. "
                    f"Recording as over_limit."
                )
                sender = self._get_sender_address(chain, tx)
                self.db.insert_deposit(
                    chain, txid, deposit_vout, amount,
                    base_address, height, "", sender
                )
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
                continue

            # Record the deposit as 'retired_pending' — requires manual
            # approval before minting.  This prevents accidental minting of
            # historical deposits that may have been handled out-of-band.
            sender = self._get_sender_address(chain, tx)
            try:
                block_hash = tx.get("blockhash", "")
            except Exception:
                block_hash = ""
            inserted = self.db.insert_deposit(
                chain, txid, deposit_vout, amount,
                base_address, height, block_hash, sender
            )
            if inserted:
                # Mark as retired_pending so it doesn't auto-mint
                row = self.db.conn.execute(
                    "SELECT id FROM deposits WHERE native_txid = ? AND native_vout = ?",
                    (txid, deposit_vout)
                ).fetchone()
                if row:
                    self.db.conn.execute(
                        "UPDATE deposits SET status = 'retired_pending' WHERE id = ?",
                        (row["id"],)
                    )
                    self.db.conn.commit()
                logger.info(
                    f"[{chain}] Retired-address deposit recorded (NEEDS MANUAL APPROVAL): "
                    f"{amount / 1e8:.8f} {coin} -> {base_address} "
                    f"(tx: {txid[:16]}... height: {height})"
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

        Uses crash-safe flow (same pattern as withdrawals):
          1. CAS: over_limit -> refunding
          2. RPC: send_to_address
          3. Record tentative_refund_txid immediately
          4. Finalize: refunding -> refunded

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

            # Step 1: CAS — mark as "refunding"
            if not self.db.mark_deposit_refunding(dep["id"]):
                logger.warning(
                    f"[{chain}] Refund CAS failed for deposit {dep['id']} "
                    f"(not in 'over_limit' state), skipping"
                )
                continue

            rpc = self.chain_config[chain]["rpc"]
            refund_coins = refund_amount / 1e8

            # Step 2: Send refund + record + finalize.
            # ALL exceptions are AMBIGUOUS (same rationale as withdrawals).
            # Never reset to 'over_limit' — leave in 'refunding' for
            # reconciliation to resolve.
            try:
                refund_txid = rpc.send_to_address(sender, refund_coins)
                self.db.update_deposit_tentative_refund_txid(
                    dep["id"], refund_txid
                )
                self.db.mark_deposit_refunded(dep["id"], refund_txid)
                logger.info(
                    f"[{chain}] AUTO-REFUND: {refund_amount / 1e8:.8f} {coin} "
                    f"back to {sender} (tx: {refund_txid[:16]}...)"
                )
            except Exception as e:
                logger.error(
                    f"[{chain}] AMBIGUOUS: Refund for deposit {dep['id']} "
                    f"exception: {e}. Left in 'refunding' for reconciliation."
                )

    def _reconcile_incomplete_refunds(self):
        """Resolve refunds stuck in 'refunding' state after a crash.

        Same logic as withdrawal reconciliation — check tentative txid
        first, fall back to wallet history, flag old stuck ones.
        """
        stuck = self.db.get_refunding_deposits()
        if not stuck:
            return

        logger.warning(
            f"RECONCILIATION: Found {len(stuck)} refund(s) in 'refunding' state"
        )

        for dep in stuck:
            chain = dep["chain"]
            rpc = self.chain_config[chain]["rpc"]
            coin = self.chain_config[chain]["coin"]
            sender = dep["sender_address"]
            did = dep["id"]
            tentative_txid = dep["tentative_refund_txid"]
            refund_coins = (dep["amount"] - 10000) / 1e8  # same fee logic

            # Strategy 1: Verify tentative txid on chain
            if tentative_txid:
                try:
                    tx_info = rpc.get_transaction(tentative_txid)
                    if tx_info:
                        self.db.mark_deposit_refunded(did, tentative_txid)
                        logger.info(
                            f"[{chain}] RECONCILED refund {did}: "
                            f"tx {tentative_txid[:16]}... confirmed"
                        )
                        continue
                except Exception:
                    pass

            # Strategy 2: Check wallet history (with time window)
            if sender:
                try:
                    recent_txs = rpc.list_transactions(100)
                    found_txid = None
                    # Get deposit's updated_at as time bound
                    dep_row = self.db.conn.execute(
                        "SELECT updated_at FROM deposits WHERE id = ?", (did,)
                    ).fetchone()
                    min_time = 0
                    if dep_row and dep_row["updated_at"]:
                        try:
                            from datetime import datetime
                            dt = datetime.fromisoformat(dep_row["updated_at"])
                            min_time = int(dt.timestamp()) - 300
                        except (ValueError, TypeError):
                            pass

                    for tx in recent_txs:
                        tx_addr = tx.get("address", "")
                        tx_amount = abs(float(tx.get("amount", 0)))
                        tx_category = tx.get("category", "")
                        tx_time = tx.get("time", 0)

                        if not (tx_category == "send"
                                and tx_addr == sender
                                and abs(tx_amount - refund_coins) < 0.00000001):
                            continue
                        if min_time and tx_time < min_time:
                            continue  # Too old

                        found_txid = tx.get("txid", "")
                        break

                    if found_txid:
                        self.db.mark_deposit_refunded(did, found_txid)
                        logger.info(
                            f"[{chain}] RECONCILED refund {did}: "
                            f"matched tx {found_txid[:16]}... in wallet history"
                        )
                        continue
                except Exception as e:
                    logger.warning(
                        f"[{chain}] Refund reconciliation failed for {did}: {e}"
                    )

            # Strategy 3: Check age before deciding.
            # If recent — safe to reset for retry (send likely failed).
            # If old (>30 min) — leave in 'refunding' for manual review
            # to avoid repeated resend risk with incomplete wallet history.
            dep_row = self.db.conn.execute(
                """SELECT CASE WHEN updated_at <= datetime('now', '-30 minutes')
                   THEN 1 ELSE 0 END as is_old FROM deposits WHERE id = ?""",
                (did,)
            ).fetchone()

            if dep_row and dep_row["is_old"]:
                logger.critical(
                    f"[{chain}] MANUAL REVIEW NEEDED: Refund for deposit {did} "
                    f"stuck in 'refunding' for >30 min. "
                    f"Amount: {refund_coins:.8f} {coin}, "
                    f"Sender: {sender}, "
                    f"Tentative TX: {tentative_txid or 'NONE'}"
                )
            else:
                self.db.reset_deposit_to_over_limit(did)
                logger.warning(
                    f"[{chain}] RECONCILED refund {did}: "
                    f"recent, not found, reset to over_limit for retry"
                )

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
        """Send native coins for confirmed burn events.

        Uses a crash-safe flow:
          1. CAS: confirmed -> sending (with durable attempt_id)
          2. RPC: send_to_address
          3. Record tentative_txid immediately
          4. Finalize: sending -> sent

        If the process crashes between steps 2-4, the reconciliation
        method (_reconcile_incomplete_sends) resolves it on next startup.
        """
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

            # Phase 3: Validate native address before sending
            if not rpc.validate_address(w["native_address"]):
                self.db.mark_withdrawal_failed(
                    w["id"], f"Invalid native address: {w['native_address']}"
                )
                logger.error(
                    f"[{chain}] Withdrawal {w['id']} rejected: "
                    f"invalid address {w['native_address']}"
                )
                continue

            # Phase 3: Reject dust withdrawals (below 0.0001 coins)
            if amount_coins < 0.0001:
                self.db.mark_withdrawal_failed(
                    w["id"], f"Amount below dust threshold: {amount_coins}"
                )
                logger.warning(
                    f"[{chain}] Withdrawal {w['id']} rejected: "
                    f"dust amount {amount_coins:.8f} {coin}"
                )
                continue

            # Step 1: Atomic CAS — mark as "sending" with durable intent
            retry_count = w["retry_count"] if w["retry_count"] else 0
            attempt_id = f"{w['id']}_{retry_count}"
            if not self.db.mark_withdrawal_sending(w["id"], attempt_id):
                logger.warning(
                    f"[{chain}] Withdrawal {w['id']} CAS failed "
                    f"(not in 'confirmed' state), skipping"
                )
                continue

            # Step 2: Send native coins + record + finalize.
            #
            # ALL exceptions are treated as AMBIGUOUS. The RPC transport
            # (raw HTTP/1.0 over socket) can throw after the server has
            # already processed the send (truncated response, connection
            # reset, decode error). We cannot distinguish "definitely not
            # sent" from "sent but response lost". Therefore:
            #   - On success: record tentative txid + finalize
            #   - On ANY exception: leave in 'sending' for reconciliation
            #   - NEVER reset to 'confirmed' here (would risk double-pay)
            try:
                native_txid = rpc.send_to_address(
                    w["native_address"], amount_coins
                )
                self.db.update_withdrawal_tentative_txid(w["id"], native_txid)
                self.db.mark_withdrawal_sent(w["id"], native_txid)
                logger.info(
                    f"[{chain}] Sent {amount_coins:.8f} {coin} "
                    f"to {w['native_address']} (tx: {native_txid[:16]}...)"
                )
            except Exception as e:
                # AMBIGUOUS: send may or may not have succeeded.
                # Leave in 'sending' — periodic reconciliation will
                # check the chain and resolve the state.
                logger.error(
                    f"[{chain}] AMBIGUOUS: Withdrawal {w['id']} send "
                    f"exception: {e}. Left in 'sending' for reconciliation."
                )

    def _reconcile_incomplete_sends(self):
        """Resolve withdrawals stuck in 'sending' state after a crash.

        Called once at startup before the main loop. For each stuck
        withdrawal:
          - If tentative_txid exists: verify it on-chain, finalize if found
          - If no tentative_txid: check list_transactions as fallback
          - If unresolvable and >30 min old: log CRITICAL, leave for manual review
        """
        stuck = self.db.get_sending_withdrawals()
        if not stuck:
            return

        logger.warning(
            f"RECONCILIATION: Found {len(stuck)} withdrawal(s) in 'sending' state"
        )

        for w in stuck:
            chain = w["chain"]
            rpc = self.chain_config[chain]["rpc"]
            coin = self.chain_config[chain]["coin"]
            amount_coins = w["amount"] / 1e8
            wid = w["id"]

            # Check age — if >30 min old with no resolution, flag for manual review
            sent_intent_at = w["sent_intent_at"]
            tentative_txid = w["tentative_txid"]

            # Strategy 1: We have a tentative txid — verify on chain
            if tentative_txid:
                try:
                    tx_info = rpc.get_transaction(tentative_txid)
                    if tx_info:
                        # Transaction exists on chain — finalize it
                        self.db.mark_withdrawal_sent(wid, tentative_txid)
                        logger.info(
                            f"[{chain}] RECONCILED withdrawal {wid}: "
                            f"tentative tx {tentative_txid[:16]}... confirmed on chain"
                        )
                        continue
                except Exception:
                    pass  # tx not found or RPC error — fall through

            # Strategy 2: No tentative txid — check wallet transaction history.
            # Use time window to avoid false-matching older historical sends
            # to the same address for the same amount.
            try:
                recent_txs = rpc.list_transactions(100)
                found_txid = None
                for tx in recent_txs:
                    tx_addr = tx.get("address", "")
                    tx_amount = abs(float(tx.get("amount", 0)))
                    tx_category = tx.get("category", "")
                    tx_time = tx.get("time", 0)

                    # Only consider sends matching address + amount
                    if not (tx_category == "send"
                            and tx_addr == w["native_address"]
                            and abs(tx_amount - amount_coins) < 0.00000001):
                        continue

                    # Time window: only match transactions created after
                    # the withdrawal was confirmed (sent_intent_at minus
                    # a 5-minute buffer for clock skew).
                    if sent_intent_at:
                        # Parse sent_intent_at to unix timestamp
                        try:
                            from datetime import datetime
                            intent_dt = datetime.fromisoformat(sent_intent_at)
                            intent_ts = int(intent_dt.timestamp()) - 300
                            if tx_time < intent_ts:
                                continue  # Too old — skip
                        except (ValueError, TypeError):
                            pass  # Can't parse — don't filter by time

                    found_txid = tx.get("txid", "")
                    break

                if found_txid:
                    self.db.mark_withdrawal_sent(wid, found_txid)
                    logger.info(
                        f"[{chain}] RECONCILED withdrawal {wid}: "
                        f"matched tx {found_txid[:16]}... in wallet history "
                        f"(time-filtered)"
                    )
                    continue
            except Exception as e:
                logger.warning(
                    f"[{chain}] Reconciliation list_transactions failed "
                    f"for withdrawal {wid}: {e}"
                )

            # Strategy 3: Unresolvable — check age
            # If no sent_intent_at or it's recent, reset to confirmed for retry
            # If old (>30 min), leave in 'sending' for manual review
            if not sent_intent_at:
                # No timestamp — likely very old or corrupted, reset
                self.db.reset_withdrawal_to_confirmed(wid)
                logger.warning(
                    f"[{chain}] RECONCILED withdrawal {wid}: "
                    f"no intent timestamp, reset to confirmed for retry"
                )
            else:
                # Check age by querying DB (SQLite datetime comparison)
                row = self.db.conn.execute(
                    """SELECT CASE WHEN sent_intent_at <= datetime('now', '-30 minutes')
                       THEN 1 ELSE 0 END as is_old FROM withdrawals WHERE id = ?""",
                    (wid,)
                ).fetchone()

                if row and row["is_old"]:
                    logger.critical(
                        f"[{chain}] MANUAL REVIEW NEEDED: Withdrawal {wid} "
                        f"stuck in 'sending' for >30 min. "
                        f"Amount: {amount_coins:.8f} {coin}, "
                        f"Address: {w['native_address']}, "
                        f"Tentative TX: {tentative_txid or 'NONE'}, "
                        f"Attempt: {w['attempt_id']}"
                    )
                else:
                    # Recent — reset to confirmed for retry
                    self.db.reset_withdrawal_to_confirmed(wid)
                    logger.warning(
                        f"[{chain}] RECONCILED withdrawal {wid}: "
                        f"recent send attempt not found, reset to confirmed"
                    )

    # ── Backing invariant monitor ───────────────────────────────────

    def _check_backing_invariant(self):
        """Verify that locked native coins >= circulating wrapped tokens.

        The correct invariant is simply: native_balance >= wrapped_supply.

        No inflight adjustment is needed because:
          - Burns reduce wrapped_supply BEFORE native coins are sent,
            so native_balance temporarily exceeds wrapped_supply (safe).
          - Deposits increase native_balance BEFORE minting, so
            native_balance temporarily exceeds wrapped_supply (safe).
          - A deficit means coins left the native wallet without a
            corresponding burn, or minted tokens without backing.
        """
        for chain, cfg in self.chain_config.items():
            contract = cfg["contract"]
            rpc = cfg["rpc"]

            if not contract:
                continue

            try:
                # Native side: bridge wallet balance (in ions/volts)
                native_balance_coins = rpc.get_balance()
                native_balance = int(round(native_balance_coins * 1e8))

                # Base side: total supply of wrapped token
                wrapped_supply = contract.functions.totalSupply().call()

                # Simple comparison — no inflight adjustment needed
                delta = native_balance - wrapped_supply
                status = "ok" if delta >= 0 else "BREACH"

                self.db.record_invariant_check(
                    chain, native_balance, wrapped_supply,
                    0, status, delta
                )

                if delta < 0:
                    # WARNING-ONLY mode: The bridge wallet on this node may not
                    # hold all reserves (e.g. old bridge addresses in operator's
                    # personal wallet). Log but do NOT auto-pause.
                    logger.warning(
                        f"[{chain}] BACKING INVARIANT WARNING: "
                        f"Native: {native_balance / 1e8:.8f}, "
                        f"Wrapped: {wrapped_supply / 1e8:.8f}, "
                        f"Delta: {delta / 1e8:.8f} (UNBACKED on this wallet). "
                        f"Operator: verify total reserves across all wallets."
                    )
                else:
                    logger.debug(
                        f"[{chain}] Invariant OK: native={native_balance / 1e8:.4f}, "
                        f"wrapped={wrapped_supply / 1e8:.4f}, delta={delta / 1e8:.4f}"
                    )

            except Exception as e:
                logger.warning(
                    f"[{chain}] Invariant check failed (non-fatal): {e}"
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
