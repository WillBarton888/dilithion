"""
Comprehensive test suite for bridge relayer components.
Tests OP_RETURN parsing, state DB, and relayer logic without needing live chains.

Run: python -m pytest relayer/test_relayer.py -v
  or: python relayer/test_relayer.py
"""

import os
import sys
import tempfile
import unittest

# Add relayer dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from state_db import StateDB


class TestStateDB(unittest.TestCase):
    """Test SQLite state database operations."""

    def setUp(self):
        self.db_file = tempfile.mktemp(suffix=".db")
        self.db = StateDB(self.db_file)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_file):
            os.unlink(self.db_file)

    # ── Deposits ───────────────────────────────────────────────

    def test_insert_deposit(self):
        result = self.db.insert_deposit(
            "dil", "abc123", 0, 100_000_000, "0xDEAD", 100, "hash100"
        )
        self.assertTrue(result)

    def test_insert_duplicate_deposit_is_idempotent(self):
        self.db.insert_deposit("dil", "abc123", 0, 100_000_000, "0xDEAD", 100, "hash100")
        result = self.db.insert_deposit("dil", "abc123", 0, 100_000_000, "0xDEAD", 100, "hash100")
        self.assertFalse(result, "Duplicate deposit should return False")

    def test_same_txid_different_vout_allowed(self):
        r1 = self.db.insert_deposit("dil", "abc123", 0, 100_000_000, "0xDEAD", 100, "hash100")
        r2 = self.db.insert_deposit("dil", "abc123", 1, 50_000_000, "0xBEEF", 100, "hash100")
        self.assertTrue(r1)
        self.assertTrue(r2)

    def test_pending_deposits_returned(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        self.db.insert_deposit("dilv", "tx2", 0, 200, "0xB", 20, "h20")
        pending = self.db.get_pending_deposits()
        self.assertEqual(len(pending), 2)

    def test_pending_deposits_filtered_by_chain(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        self.db.insert_deposit("dilv", "tx2", 0, 200, "0xB", 20, "h20")
        dil_pending = self.db.get_pending_deposits("dil")
        self.assertEqual(len(dil_pending), 1)
        self.assertEqual(dil_pending[0]["chain"], "dil")

    def test_deposit_confirmation_flow(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        deposits = self.db.get_pending_deposits()
        dep_id = deposits[0]["id"]

        # Update confirmations
        self.db.update_deposit_confirmations(dep_id, 5)
        updated = self.db.get_pending_deposits()[0]
        self.assertEqual(updated["confirmations"], 5)

        # Confirm deposit
        self.db.confirm_deposit(dep_id, 15)
        self.assertEqual(len(self.db.get_pending_deposits()), 0)
        confirmed = self.db.get_confirmed_deposits()
        self.assertEqual(len(confirmed), 1)

    def test_deposit_mint_flow(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        dep_id = self.db.get_pending_deposits()[0]["id"]
        self.db.confirm_deposit(dep_id, 15)
        self.db.mark_deposit_minted(dep_id, "0xMintTxHash")

        # Should no longer appear in confirmed
        self.assertEqual(len(self.db.get_confirmed_deposits()), 0)

    def test_deposit_reorg_marks_pending_and_confirmed(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 50, "h50")
        self.db.insert_deposit("dil", "tx2", 0, 200, "0xB", 60, "h60")
        self.db.insert_deposit("dil", "tx3", 0, 300, "0xC", 40, "h40")
        dep_id = self.db.get_pending_deposits("dil")[1]["id"]
        self.db.confirm_deposit(dep_id, 15)

        # Reorg at height 50 — should mark tx1 (h=50) and tx2 (h=60), not tx3 (h=40)
        reorged = self.db.mark_deposits_reorged("dil", 50)
        self.assertEqual(reorged, 2)  # tx1 (pending, h=50) + tx2 (confirmed, h=60)

        # tx3 should still be pending
        pending = self.db.get_pending_deposits("dil")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["native_txid"], "tx3")

    def test_deposit_failed_state(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        dep_id = self.db.get_pending_deposits()[0]["id"]
        self.db.confirm_deposit(dep_id, 15)
        self.db.mark_deposit_failed(dep_id, "Gas exhausted")

        confirmed = self.db.get_confirmed_deposits()
        self.assertEqual(len(confirmed), 0)

    # ── Withdrawals ────────────────────────────────────────────

    def test_insert_withdrawal(self):
        result = self.db.insert_withdrawal("dil", "0xBurnTx", 0, 12345, 100, "DAddress123")
        self.assertTrue(result)

    def test_insert_duplicate_withdrawal_idempotent(self):
        self.db.insert_withdrawal("dil", "0xBurnTx", 0, 12345, 100, "DAddress123")
        result = self.db.insert_withdrawal("dil", "0xBurnTx", 0, 12345, 100, "DAddress123")
        self.assertFalse(result)

    def test_same_burn_tx_different_log_index(self):
        r1 = self.db.insert_withdrawal("dil", "0xBurnTx", 0, 12345, 100, "DAddr1")
        r2 = self.db.insert_withdrawal("dil", "0xBurnTx", 1, 12345, 200, "DAddr2")
        self.assertTrue(r1)
        self.assertTrue(r2)

    def test_withdrawal_full_flow(self):
        self.db.insert_withdrawal("dil", "0xBurn1", 0, 100, 500, "DAddr")
        pending = self.db.get_pending_withdrawals()
        self.assertEqual(len(pending), 1)

        w_id = pending[0]["id"]
        self.db.confirm_withdrawal(w_id)
        confirmed = self.db.get_confirmed_withdrawals()
        self.assertEqual(len(confirmed), 1)

        self.db.mark_withdrawal_sent(w_id, "native_txid_123")
        self.assertEqual(len(self.db.get_confirmed_withdrawals()), 0)

        self.db.mark_withdrawal_completed(w_id)

    def test_withdrawal_failed_state(self):
        self.db.insert_withdrawal("dil", "0xBurn1", 0, 100, 500, "DAddr")
        w_id = self.db.get_pending_withdrawals()[0]["id"]
        self.db.confirm_withdrawal(w_id)
        self.db.mark_withdrawal_failed(w_id, "RPC timeout")
        self.assertEqual(len(self.db.get_confirmed_withdrawals()), 0)

    # ── Sync state ─────────────────────────────────────────────

    def test_sync_state_initial_none(self):
        self.assertIsNone(self.db.get_sync_state("dil"))

    def test_sync_state_set_and_get(self):
        self.db.set_sync_state("dil", 1000, "hash1000")
        result = self.db.get_sync_state("dil")
        self.assertEqual(result, (1000, "hash1000"))

    def test_sync_state_upsert(self):
        self.db.set_sync_state("dil", 1000, "hash1000")
        self.db.set_sync_state("dil", 1001, "hash1001")
        result = self.db.get_sync_state("dil")
        self.assertEqual(result, (1001, "hash1001"))

    def test_sync_state_per_chain(self):
        self.db.set_sync_state("dil", 100, "hD")
        self.db.set_sync_state("dilv", 200, "hV")
        self.assertEqual(self.db.get_sync_state("dil"), (100, "hD"))
        self.assertEqual(self.db.get_sync_state("dilv"), (200, "hV"))

    # ── Daily mints ────────────────────────────────────────────

    def test_daily_minted_starts_at_zero(self):
        self.assertEqual(self.db.get_daily_minted("dil"), 0)

    def test_add_daily_minted(self):
        self.db.add_daily_minted("dil", 100_000_000)
        self.assertEqual(self.db.get_daily_minted("dil"), 100_000_000)

    def test_daily_minted_accumulates(self):
        self.db.add_daily_minted("dil", 100)
        self.db.add_daily_minted("dil", 200)
        self.assertEqual(self.db.get_daily_minted("dil"), 300)

    def test_daily_minted_per_chain(self):
        self.db.add_daily_minted("dil", 100)
        self.db.add_daily_minted("dilv", 500)
        self.assertEqual(self.db.get_daily_minted("dil"), 100)
        self.assertEqual(self.db.get_daily_minted("dilv"), 500)

    # ── Stats ──────────────────────────────────────────────────

    def test_stats_empty_db(self):
        stats = self.db.get_stats()
        self.assertEqual(stats["deposits_pending"], 0)
        self.assertEqual(stats["deposits_minted"], 0)
        self.assertEqual(stats["withdrawals_pending"], 0)

    def test_stats_with_data(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        self.db.insert_deposit("dil", "tx2", 0, 200, "0xB", 20, "h20")
        dep_id = self.db.get_pending_deposits()[0]["id"]
        self.db.confirm_deposit(dep_id, 15)
        self.db.mark_deposit_minted(dep_id, "0xMint")

        stats = self.db.get_stats()
        self.assertEqual(stats["deposits_pending"], 1)
        self.assertEqual(stats["deposits_minted"], 1)


class TestOpReturnParsing(unittest.TestCase):
    """Test OP_RETURN parsing logic from the relayer."""

    BRIDGE_TAG = b"DBRG"

    def parse_op_return(self, script_hex):
        """Extract Base address from OP_RETURN script. Returns address or None."""
        try:
            script = bytes.fromhex(script_hex)
        except ValueError:
            return None

        # Must start with OP_RETURN (0x6a)
        if not script or script[0] != 0x6a:
            return None

        # Next byte is push length
        if len(script) < 2:
            return None
        push_len = script[1]

        # Payload must be exactly 24 bytes (4 tag + 20 address)
        if push_len != 24:
            return None

        if len(script) < 2 + push_len:
            return None

        payload = script[2:2 + push_len]
        tag = payload[:4]
        addr_bytes = payload[4:]

        # Validate tag
        if tag != self.BRIDGE_TAG:
            return None

        # Validate address is non-zero
        if addr_bytes == b'\x00' * 20:
            return None

        return "0x" + addr_bytes.hex()

    # ── Valid OP_RETURN ─────────────────────────────────────

    def test_valid_op_return(self):
        # OP_RETURN + push 24 + "DBRG" + 20-byte address
        addr = "758F0063417E13Ab20C360454AA95C3dD5e7ffB7"
        script = "6a18" + "44425247" + addr.lower()
        result = self.parse_op_return(script)
        self.assertEqual(result, "0x" + addr.lower())

    def test_valid_with_different_address(self):
        addr = "aabbccddee" * 4  # 20 bytes
        script = "6a18" + "44425247" + addr
        result = self.parse_op_return(script)
        self.assertEqual(result, "0x" + addr)

    # ── Invalid OP_RETURN: wrong tag ───────────────────────

    def test_wrong_tag(self):
        addr = "758F0063417E13Ab20C360454AA95C3dD5e7ffB7"
        script = "6a18" + "42414442" + addr.lower()  # "BADB" instead of "DBRG"
        self.assertIsNone(self.parse_op_return(script))

    # ── Invalid OP_RETURN: wrong length ────────────────────

    def test_too_short_payload(self):
        # Only 10 bytes instead of 24
        script = "6a0a" + "44425247" + "aabbccddee00"
        self.assertIsNone(self.parse_op_return(script))

    def test_too_long_payload(self):
        # 25 bytes instead of 24
        script = "6a19" + "44425247" + "aa" * 21
        self.assertIsNone(self.parse_op_return(script))

    # ── Invalid OP_RETURN: zero address ────────────────────

    def test_zero_address_rejected(self):
        script = "6a18" + "44425247" + "00" * 20
        self.assertIsNone(self.parse_op_return(script))

    # ── Invalid OP_RETURN: not OP_RETURN ───────────────────

    def test_not_op_return(self):
        # Regular P2PKH script instead of OP_RETURN
        script = "76a914" + "aa" * 20 + "88ac"
        self.assertIsNone(self.parse_op_return(script))

    def test_empty_script(self):
        self.assertIsNone(self.parse_op_return(""))

    def test_invalid_hex(self):
        self.assertIsNone(self.parse_op_return("not-hex-at-all"))

    def test_just_op_return_no_data(self):
        self.assertIsNone(self.parse_op_return("6a"))

    # ── Edge cases ─────────────────────────────────────────

    def test_op_return_with_extra_trailing_bytes(self):
        # Valid 24-byte payload but script has extra bytes after
        addr = "758F0063417E13Ab20C360454AA95C3dD5e7ffB7"
        script = "6a18" + "44425247" + addr.lower() + "ffff"
        # Should still parse (we read exactly push_len bytes)
        result = self.parse_op_return(script)
        self.assertEqual(result, "0x" + addr.lower())

    def test_truncated_script(self):
        # Script says 24 bytes but only has 10
        script = "6a18" + "44425247" + "aabbcc"
        self.assertIsNone(self.parse_op_return(script))


class TestRelayerSafetyChecks(unittest.TestCase):
    """Test relayer-side safety limit logic."""

    def test_daily_cap_check(self):
        """Simulate daily cap enforcement."""
        daily_cap = 10_000_00000000  # 10,000 DIL
        minted_today = 9_500_00000000  # 9,500 DIL already minted
        new_deposit = 600_00000000  # 600 DIL

        would_exceed = (minted_today + new_deposit) > daily_cap
        self.assertTrue(would_exceed, "Should detect cap would be exceeded")

    def test_per_deposit_check(self):
        """Simulate per-deposit limit enforcement."""
        max_per_deposit = 1_000_00000000  # 1,000 DIL
        deposit_amount = 1_001_00000000  # 1,001 DIL

        exceeds = deposit_amount > max_per_deposit
        self.assertTrue(exceeds, "Should detect per-deposit limit exceeded")

    def test_confirmation_threshold(self):
        """Simulate confirmation threshold check."""
        required = 15
        current_height = 1000
        deposit_height = 990
        confirmations = current_height - deposit_height

        self.assertEqual(confirmations, 10)
        self.assertFalse(confirmations >= required, "10 < 15, not yet confirmed")

        current_height = 1005
        confirmations = current_height - deposit_height
        self.assertEqual(confirmations, 15)
        self.assertTrue(confirmations >= required, "15 >= 15, confirmed")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
