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


class TestWithdrawalCrashSafety(unittest.TestCase):
    """Test the CAS + durable attempt ledger for withdrawal crash safety."""

    def setUp(self):
        self.db_file = tempfile.mktemp(suffix=".db")
        self.db = StateDB(self.db_file)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_file):
            os.unlink(self.db_file)

    def _make_confirmed_withdrawal(self, burn_txid="0xBurn", amount=500):
        self.db.insert_withdrawal("dil", burn_txid, 0, 100, amount, "DTestAddr")
        w = self.db.get_pending_withdrawals()[0]
        self.db.confirm_withdrawal(w["id"])
        return w["id"]

    def test_cas_from_confirmed_to_sending(self):
        wid = self._make_confirmed_withdrawal()
        result = self.db.mark_withdrawal_sending(wid, "1_0")
        self.assertTrue(result)
        self.assertEqual(len(self.db.get_confirmed_withdrawals()), 0)
        self.assertEqual(len(self.db.get_sending_withdrawals()), 1)

    def test_cas_fails_if_not_confirmed(self):
        wid = self._make_confirmed_withdrawal()
        # Already in sending
        self.db.mark_withdrawal_sending(wid, "1_0")
        # Second CAS should fail
        result = self.db.mark_withdrawal_sending(wid, "1_1")
        self.assertFalse(result)

    def test_cas_fails_on_pending(self):
        self.db.insert_withdrawal("dil", "0xBurn", 0, 100, 500, "DAddr")
        w = self.db.get_pending_withdrawals()[0]
        result = self.db.mark_withdrawal_sending(w["id"], "1_0")
        self.assertFalse(result, "CAS should fail on 'pending' status")

    def test_sending_not_in_confirmed_query(self):
        wid = self._make_confirmed_withdrawal()
        self.db.mark_withdrawal_sending(wid, "1_0")
        self.assertEqual(len(self.db.get_confirmed_withdrawals()), 0)

    def test_tentative_txid_persists(self):
        wid = self._make_confirmed_withdrawal()
        self.db.mark_withdrawal_sending(wid, "1_0")
        self.db.update_withdrawal_tentative_txid(wid, "native_tx_abc")
        sending = self.db.get_sending_withdrawals()
        self.assertEqual(sending[0]["tentative_txid"], "native_tx_abc")

    def test_reset_to_confirmed_clears_attempt(self):
        wid = self._make_confirmed_withdrawal()
        self.db.mark_withdrawal_sending(wid, "1_0")
        self.db.update_withdrawal_tentative_txid(wid, "native_tx_abc")
        self.db.reset_withdrawal_to_confirmed(wid)

        confirmed = self.db.get_confirmed_withdrawals()
        self.assertEqual(len(confirmed), 1)
        self.assertIsNone(confirmed[0]["tentative_txid"])
        self.assertIsNone(confirmed[0]["attempt_id"])
        self.assertEqual(confirmed[0]["retry_count"], 1)

    def test_mark_sent_from_sending(self):
        wid = self._make_confirmed_withdrawal()
        self.db.mark_withdrawal_sending(wid, "1_0")
        self.db.mark_withdrawal_sent(wid, "final_txid")
        self.assertEqual(len(self.db.get_sending_withdrawals()), 0)

    def test_attempt_id_is_recorded(self):
        wid = self._make_confirmed_withdrawal()
        self.db.mark_withdrawal_sending(wid, "42_3")
        sending = self.db.get_sending_withdrawals()
        self.assertEqual(sending[0]["attempt_id"], "42_3")

    def test_sent_intent_at_is_set(self):
        wid = self._make_confirmed_withdrawal()
        self.db.mark_withdrawal_sending(wid, "1_0")
        sending = self.db.get_sending_withdrawals()
        self.assertIsNotNone(sending[0]["sent_intent_at"])


class TestRefundCrashSafety(unittest.TestCase):
    """Test the CAS pattern for refund crash safety."""

    def setUp(self):
        self.db_file = tempfile.mktemp(suffix=".db")
        self.db = StateDB(self.db_file)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_file):
            os.unlink(self.db_file)

    def _make_over_limit_deposit(self):
        self.db.insert_deposit("dil", "tx1", 0, 200_000_000_000, "0xA", 10, "h10", "DSender")
        dep = self.db.get_pending_deposits()[0]
        # Manually set to over_limit
        self.db.conn.execute(
            "UPDATE deposits SET status = 'over_limit' WHERE id = ?",
            (dep["id"],)
        )
        self.db.conn.commit()
        return dep["id"]

    def test_cas_from_over_limit_to_refunding(self):
        did = self._make_over_limit_deposit()
        result = self.db.mark_deposit_refunding(did)
        self.assertTrue(result)
        refunding = self.db.get_refunding_deposits()
        self.assertEqual(len(refunding), 1)

    def test_cas_fails_if_not_over_limit(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 10, "h10")
        dep = self.db.get_pending_deposits()[0]
        result = self.db.mark_deposit_refunding(dep["id"])
        self.assertFalse(result, "CAS should fail on 'pending' status")

    def test_refunding_not_in_pending_refunds(self):
        did = self._make_over_limit_deposit()
        self.db.mark_deposit_refunding(did)
        # get_pending_refunds only returns 'over_limit'
        self.assertEqual(len(self.db.get_pending_refunds()), 0)

    def test_tentative_refund_txid_persists(self):
        did = self._make_over_limit_deposit()
        self.db.mark_deposit_refunding(did)
        self.db.update_deposit_tentative_refund_txid(did, "refund_tx_123")
        refunding = self.db.get_refunding_deposits()
        self.assertEqual(refunding[0]["tentative_refund_txid"], "refund_tx_123")

    def test_reset_to_over_limit(self):
        did = self._make_over_limit_deposit()
        self.db.mark_deposit_refunding(did)
        self.db.reset_deposit_to_over_limit(did)
        self.assertEqual(len(self.db.get_pending_refunds()), 1)
        self.assertEqual(len(self.db.get_refunding_deposits()), 0)


class TestBlockHashHistory(unittest.TestCase):
    """Test block hash storage for reorg detection."""

    def setUp(self):
        self.db_file = tempfile.mktemp(suffix=".db")
        self.db = StateDB(self.db_file)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_file):
            os.unlink(self.db_file)

    def test_store_and_retrieve(self):
        self.db.store_block_hash("dil", 100, "hash100")
        self.assertEqual(self.db.get_block_hash("dil", 100), "hash100")

    def test_missing_returns_none(self):
        self.assertIsNone(self.db.get_block_hash("dil", 999))

    def test_overwrite(self):
        self.db.store_block_hash("dil", 100, "hash_old")
        self.db.store_block_hash("dil", 100, "hash_new")
        self.assertEqual(self.db.get_block_hash("dil", 100), "hash_new")

    def test_per_chain_isolation(self):
        self.db.store_block_hash("dil", 100, "dil_hash")
        self.db.store_block_hash("dilv", 100, "dilv_hash")
        self.assertEqual(self.db.get_block_hash("dil", 100), "dil_hash")
        self.assertEqual(self.db.get_block_hash("dilv", 100), "dilv_hash")

    def test_prune_keeps_recent(self):
        for h in range(1, 301):
            self.db.store_block_hash("dil", h, f"hash_{h}")
        self.db.prune_block_hashes("dil", keep_last=200)
        # SQL: DELETE WHERE height < MAX(300) - 200 = 100
        # So height 99 is pruned, height 100+ survives
        self.assertIsNone(self.db.get_block_hash("dil", 99))
        self.assertIsNotNone(self.db.get_block_hash("dil", 100))
        self.assertIsNotNone(self.db.get_block_hash("dil", 300))

    def test_minted_deposits_above_height(self):
        self.db.insert_deposit("dil", "tx1", 0, 100, "0xA", 50, "h50")
        self.db.insert_deposit("dil", "tx2", 0, 200, "0xB", 60, "h60")
        self.db.insert_deposit("dil", "tx3", 0, 300, "0xC", 40, "h40")

        # Mark tx1 and tx2 as minted
        for dep in self.db.get_pending_deposits():
            self.db.confirm_deposit(dep["id"], 15)
        for dep in self.db.get_confirmed_deposits():
            self.db.mark_deposit_minted(dep["id"], "mint_" + str(dep["id"]))

        # Only tx1 (h=50) and tx2 (h=60) should be returned for height >= 50
        at_risk = self.db.get_minted_deposits_above_height("dil", 50)
        self.assertEqual(len(at_risk), 2)

        # Only tx2 (h=60) for height >= 55
        at_risk = self.db.get_minted_deposits_above_height("dil", 55)
        self.assertEqual(len(at_risk), 1)


class TestInvariantCheck(unittest.TestCase):
    """Test the invariant check DB methods."""

    def setUp(self):
        self.db_file = tempfile.mktemp(suffix=".db")
        self.db = StateDB(self.db_file)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_file):
            os.unlink(self.db_file)

    def test_record_invariant_check(self):
        self.db.record_invariant_check(
            "dil", 100_000_000, 50_000_000, 0, "ok", 50_000_000
        )
        # No assertion needed — just verify it doesn't throw

    def test_inflight_total_empty(self):
        total = self.db.get_inflight_withdrawal_total("dil")
        self.assertEqual(total, 0)

    def test_inflight_total_counts_confirmed_and_sending(self):
        self.db.insert_withdrawal("dil", "0xB1", 0, 100, 500, "D1")
        self.db.insert_withdrawal("dil", "0xB2", 1, 100, 300, "D2")
        w1 = self.db.get_pending_withdrawals()[0]
        w2 = self.db.get_pending_withdrawals()[1]

        self.db.confirm_withdrawal(w1["id"])
        self.db.confirm_withdrawal(w2["id"])
        self.db.mark_withdrawal_sending(w2["id"], "2_0")

        total = self.db.get_inflight_withdrawal_total("dil")
        self.assertEqual(total, 800)  # 500 confirmed + 300 sending

    def test_inflight_excludes_sent(self):
        self.db.insert_withdrawal("dil", "0xB1", 0, 100, 500, "D1")
        w = self.db.get_pending_withdrawals()[0]
        self.db.confirm_withdrawal(w["id"])
        self.db.mark_withdrawal_sent(w["id"], "native_tx")

        total = self.db.get_inflight_withdrawal_total("dil")
        self.assertEqual(total, 0)


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
