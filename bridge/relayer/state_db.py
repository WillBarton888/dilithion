"""SQLite state database for bridge relayer — crash-safe, idempotent."""

import sqlite3
import logging
from datetime import date

logger = logging.getLogger(__name__)


class StateDB:
    """Manages bridge state in SQLite with transactional safety."""

    def __init__(self, db_path: str = "bridge_state.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS deposits (
                id INTEGER PRIMARY KEY,
                chain TEXT NOT NULL,
                native_txid TEXT NOT NULL,
                native_vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                base_address TEXT NOT NULL,
                block_height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                confirmations INTEGER DEFAULT 0,
                mint_txid TEXT,
                status TEXT DEFAULT 'pending',
                error_msg TEXT,
                retry_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(native_txid, native_vout)
            );

            CREATE TABLE IF NOT EXISTS withdrawals (
                id INTEGER PRIMARY KEY,
                chain TEXT NOT NULL,
                burn_txid TEXT NOT NULL,
                burn_log_index INTEGER NOT NULL,
                burn_block_number INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                native_address TEXT NOT NULL,
                native_txid TEXT,
                status TEXT DEFAULT 'pending',
                error_msg TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(burn_txid, burn_log_index)
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                chain TEXT PRIMARY KEY,
                last_block_height INTEGER NOT NULL,
                last_block_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daily_mints (
                chain TEXT NOT NULL,
                date TEXT NOT NULL,
                total_minted INTEGER DEFAULT 0,
                PRIMARY KEY(chain, date)
            );
        """)
        self.conn.commit()
        self._migrate()

    def _migrate(self):
        """Add columns that may not exist in older DBs."""
        try:
            self.conn.execute("SELECT retry_count FROM deposits LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE deposits ADD COLUMN retry_count INTEGER DEFAULT 0")
            self.conn.commit()
            logger.info("Migrated deposits table: added retry_count column")

        try:
            self.conn.execute("SELECT sender_address FROM deposits LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE deposits ADD COLUMN sender_address TEXT")
            self.conn.commit()
            logger.info("Migrated deposits table: added sender_address column")

        try:
            self.conn.execute("SELECT refund_txid FROM deposits LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE deposits ADD COLUMN refund_txid TEXT")
            self.conn.commit()
            logger.info("Migrated deposits table: added refund_txid column")

        # Phase 0: Refund idempotency — tentative refund txid
        try:
            self.conn.execute("SELECT tentative_refund_txid FROM deposits LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE deposits ADD COLUMN tentative_refund_txid TEXT")
            self.conn.commit()
            logger.info("Migrated deposits table: added tentative_refund_txid column")

        # Phase 0: Withdrawal crash-safety — durable attempt ledger
        try:
            self.conn.execute("SELECT tentative_txid FROM withdrawals LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE withdrawals ADD COLUMN tentative_txid TEXT")
            self.conn.commit()
            logger.info("Migrated withdrawals table: added tentative_txid column")

        try:
            self.conn.execute("SELECT attempt_id FROM withdrawals LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE withdrawals ADD COLUMN attempt_id TEXT")
            self.conn.commit()
            logger.info("Migrated withdrawals table: added attempt_id column")

        try:
            self.conn.execute("SELECT sent_intent_at FROM withdrawals LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE withdrawals ADD COLUMN sent_intent_at TIMESTAMP")
            self.conn.commit()
            logger.info("Migrated withdrawals table: added sent_intent_at column")

        try:
            self.conn.execute("SELECT retry_count FROM withdrawals LIMIT 1")
        except sqlite3.OperationalError:
            self.conn.execute("ALTER TABLE withdrawals ADD COLUMN retry_count INTEGER DEFAULT 0")
            self.conn.commit()
            logger.info("Migrated withdrawals table: added retry_count column")

        # Phase 1: Block hash history for reorg detection
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS block_hashes (
                chain TEXT NOT NULL,
                height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                PRIMARY KEY(chain, height)
            )
        """)
        self.conn.commit()

        # Phase 3b: Invariant check history
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS invariant_checks (
                id INTEGER PRIMARY KEY,
                chain TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                native_balance INTEGER NOT NULL,
                wrapped_supply INTEGER NOT NULL,
                inflight_withdrawals INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                delta INTEGER NOT NULL
            )
        """)
        self.conn.commit()

    # ── Sync state ───────────────────────────────────────────────────

    def get_sync_state(self, chain: str):
        """Get last processed block for a chain. Returns (height, hash) or None."""
        row = self.conn.execute(
            "SELECT last_block_height, last_block_hash FROM sync_state WHERE chain = ?",
            (chain,)
        ).fetchone()
        if row:
            return row["last_block_height"], row["last_block_hash"]
        return None

    def set_sync_state(self, chain: str, height: int, block_hash: str):
        self.conn.execute(
            """INSERT INTO sync_state (chain, last_block_height, last_block_hash)
               VALUES (?, ?, ?)
               ON CONFLICT(chain) DO UPDATE SET
                   last_block_height = excluded.last_block_height,
                   last_block_hash = excluded.last_block_hash""",
            (chain, height, block_hash)
        )
        self.conn.commit()

    # ── Deposits ─────────────────────────────────────────────────────

    def insert_deposit(self, chain: str, native_txid: str, native_vout: int,
                       amount: int, base_address: str, block_height: int,
                       block_hash: str, sender_address: str = None) -> bool:
        """Insert a new deposit. Returns False if duplicate (idempotent)."""
        try:
            self.conn.execute(
                """INSERT INTO deposits
                   (chain, native_txid, native_vout, amount, base_address,
                    block_height, block_hash, sender_address)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (chain, native_txid, native_vout, amount, base_address,
                 block_height, block_hash, sender_address)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.debug(f"Duplicate deposit ignored: {native_txid}:{native_vout}")
            return False

    def mark_deposit_refunding(self, deposit_id: int) -> bool:
        """Atomic CAS: transition from 'over_limit' to 'refunding'.

        Returns True if transition succeeded, False if deposit was not
        in 'over_limit' state.
        """
        cursor = self.conn.execute(
            """UPDATE deposits SET status = 'refunding',
               updated_at = CURRENT_TIMESTAMP
               WHERE id = ? AND status = 'over_limit'""",
            (deposit_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def update_deposit_tentative_refund_txid(self, deposit_id: int,
                                              tentative_txid: str):
        """Record the refund txid immediately after RPC send."""
        self.conn.execute(
            """UPDATE deposits SET tentative_refund_txid = ?,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (tentative_txid, deposit_id)
        )
        self.conn.commit()

    def mark_deposit_refunded(self, deposit_id: int, refund_txid: str):
        """Mark deposit as refunded (coins sent back to sender)."""
        self.conn.execute(
            """UPDATE deposits SET status = 'refunded', refund_txid = ?,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (refund_txid, deposit_id)
        )
        self.conn.commit()

    def reset_deposit_to_over_limit(self, deposit_id: int):
        """Reset a stuck 'refunding' deposit back to 'over_limit' for retry."""
        self.conn.execute(
            """UPDATE deposits SET status = 'over_limit',
               tentative_refund_txid = NULL,
               retry_count = COALESCE(retry_count, 0) + 1,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (deposit_id,)
        )
        self.conn.commit()

    def get_pending_refunds(self):
        """Get deposits marked for refund that haven't been sent yet."""
        return self.conn.execute(
            "SELECT * FROM deposits WHERE status = 'over_limit'"
        ).fetchall()

    def get_refunding_deposits(self):
        """Get deposits in 'refunding' state (in-flight or crashed)."""
        return self.conn.execute(
            "SELECT * FROM deposits WHERE status = 'refunding'"
        ).fetchall()

    def get_pending_deposits(self, chain: str = None):
        """Get deposits needing confirmation updates."""
        if chain:
            return self.conn.execute(
                "SELECT * FROM deposits WHERE status = 'pending' AND chain = ?",
                (chain,)
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM deposits WHERE status = 'pending'"
        ).fetchall()

    def get_confirmed_deposits(self):
        """Get deposits ready for minting."""
        return self.conn.execute(
            "SELECT * FROM deposits WHERE status = 'confirmed'"
        ).fetchall()

    def update_deposit_confirmations(self, deposit_id: int, confirmations: int):
        self.conn.execute(
            """UPDATE deposits SET confirmations = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (confirmations, deposit_id)
        )
        self.conn.commit()

    def confirm_deposit(self, deposit_id: int, confirmations: int):
        """Mark deposit as confirmed (ready to mint)."""
        self.conn.execute(
            """UPDATE deposits SET status = 'confirmed', confirmations = ?,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (confirmations, deposit_id)
        )
        self.conn.commit()

    def mark_deposit_minted(self, deposit_id: int, mint_txid: str):
        """Mark deposit as minted on Base."""
        self.conn.execute(
            """UPDATE deposits SET status = 'minted', mint_txid = ?,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (mint_txid, deposit_id)
        )
        self.conn.commit()

    def mark_deposit_failed(self, deposit_id: int, error: str):
        self.conn.execute(
            """UPDATE deposits SET status = 'failed', error_msg = ?,
               retry_count = COALESCE(retry_count, 0) + 1,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (error, deposit_id)
        )
        self.conn.commit()

    def get_retryable_deposits(self, max_retries: int = 3,
                               cooldown_minutes: int = 5):
        """Get failed deposits eligible for retry.

        Transient errors (contract cap exceeded, nonce issues) get unlimited
        retries with a longer cooldown — the cap resets daily so these will
        eventually succeed.  Other errors use the original 3-retry limit.
        """
        return self.conn.execute(
            """SELECT * FROM deposits
               WHERE status = 'failed'
                 AND (
                     -- Transient errors: unlimited retries, 60 min cooldown
                     (error_msg IN ('Mint tx reverted')
                      AND updated_at <= datetime('now', '-60 minutes'))
                     OR
                     -- Other errors: capped retries, short cooldown
                     (error_msg NOT IN ('Mint tx reverted')
                      AND COALESCE(retry_count, 0) < ?
                      AND updated_at <= datetime('now', ?))
                 )""",
            (max_retries, f'-{cooldown_minutes} minutes')
        ).fetchall()

    def mark_deposits_reorged(self, chain: str, min_height: int):
        """Mark all deposits at or above min_height as reorged."""
        cursor = self.conn.execute(
            """UPDATE deposits SET status = 'reorged', updated_at = CURRENT_TIMESTAMP
               WHERE chain = ? AND block_height >= ? AND status IN ('pending', 'confirmed')""",
            (chain, min_height)
        )
        self.conn.commit()
        return cursor.rowcount

    # ── Withdrawals ──────────────────────────────────────────────────

    def insert_withdrawal(self, chain: str, burn_txid: str, burn_log_index: int,
                          burn_block_number: int, amount: int,
                          native_address: str) -> bool:
        """Insert a new withdrawal. Returns False if duplicate."""
        try:
            self.conn.execute(
                """INSERT INTO withdrawals
                   (chain, burn_txid, burn_log_index, burn_block_number,
                    amount, native_address)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (chain, burn_txid, burn_log_index, burn_block_number,
                 amount, native_address)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.debug(f"Duplicate withdrawal ignored: {burn_txid}:{burn_log_index}")
            return False

    def get_pending_withdrawals(self):
        """Get withdrawals awaiting Base confirmation."""
        return self.conn.execute(
            "SELECT * FROM withdrawals WHERE status = 'pending'"
        ).fetchall()

    def get_confirmed_withdrawals(self):
        """Get withdrawals ready to send on native chain."""
        return self.conn.execute(
            "SELECT * FROM withdrawals WHERE status = 'confirmed'"
        ).fetchall()

    def confirm_withdrawal(self, withdrawal_id: int):
        """Mark withdrawal as Base-confirmed, ready to send."""
        self.conn.execute(
            """UPDATE withdrawals SET status = 'confirmed',
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (withdrawal_id,)
        )
        self.conn.commit()

    def mark_withdrawal_sending(self, withdrawal_id: int, attempt_id: str) -> bool:
        """Atomic CAS: transition from 'confirmed' to 'sending'.

        Returns True if transition succeeded, False if withdrawal was not
        in 'confirmed' state (already being processed or already sent).
        """
        cursor = self.conn.execute(
            """UPDATE withdrawals
               SET status = 'sending', attempt_id = ?,
                   sent_intent_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = ? AND status = 'confirmed'""",
            (attempt_id, withdrawal_id)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def update_withdrawal_tentative_txid(self, withdrawal_id: int,
                                         tentative_txid: str):
        """Record the native txid immediately after RPC send, before
        finalizing.  This is the durable intent record that survives crashes."""
        self.conn.execute(
            """UPDATE withdrawals SET tentative_txid = ?,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (tentative_txid, withdrawal_id)
        )
        self.conn.commit()

    def get_sending_withdrawals(self):
        """Get withdrawals in 'sending' state (in-flight or crashed)."""
        return self.conn.execute(
            "SELECT * FROM withdrawals WHERE status = 'sending'"
        ).fetchall()

    def mark_withdrawal_sent(self, withdrawal_id: int, native_txid: str):
        """Finalize a withdrawal as sent. Works from both 'sending' and
        'confirmed' states (the latter for reconciliation recovery)."""
        self.conn.execute(
            """UPDATE withdrawals SET status = 'sent', native_txid = ?,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (native_txid, withdrawal_id)
        )
        self.conn.commit()

    def reset_withdrawal_to_confirmed(self, withdrawal_id: int):
        """Reset a stuck 'sending' withdrawal back to 'confirmed' for retry.
        Clears attempt metadata so it gets a fresh attempt."""
        self.conn.execute(
            """UPDATE withdrawals SET status = 'confirmed',
               attempt_id = NULL, tentative_txid = NULL,
               sent_intent_at = NULL, retry_count = COALESCE(retry_count, 0) + 1,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (withdrawal_id,)
        )
        self.conn.commit()

    def mark_withdrawal_completed(self, withdrawal_id: int):
        self.conn.execute(
            """UPDATE withdrawals SET status = 'completed',
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (withdrawal_id,)
        )
        self.conn.commit()

    def mark_withdrawal_failed(self, withdrawal_id: int, error: str):
        self.conn.execute(
            """UPDATE withdrawals SET status = 'failed', error_msg = ?,
               retry_count = COALESCE(retry_count, 0) + 1,
               updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (error, withdrawal_id)
        )
        self.conn.commit()

    # ── Daily mint tracking ──────────────────────────────────────────

    def get_daily_minted(self, chain: str) -> int:
        """Get total minted today for a chain."""
        today = date.today().isoformat()
        row = self.conn.execute(
            "SELECT total_minted FROM daily_mints WHERE chain = ? AND date = ?",
            (chain, today)
        ).fetchone()
        return row["total_minted"] if row else 0

    def add_daily_minted(self, chain: str, amount: int):
        """Add to today's mint total."""
        today = date.today().isoformat()
        self.conn.execute(
            """INSERT INTO daily_mints (chain, date, total_minted)
               VALUES (?, ?, ?)
               ON CONFLICT(chain, date) DO UPDATE SET
                   total_minted = total_minted + excluded.total_minted""",
            (chain, today, amount)
        )
        self.conn.commit()

    # ── Stats ────────────────────────────────────────────────────────

    # ── Block hash history (reorg detection) ───────────────────────

    def store_block_hash(self, chain: str, height: int, block_hash: str):
        """Store a block hash for reorg detection walkback."""
        self.conn.execute(
            """INSERT INTO block_hashes (chain, height, block_hash)
               VALUES (?, ?, ?)
               ON CONFLICT(chain, height) DO UPDATE SET
                   block_hash = excluded.block_hash""",
            (chain, height, block_hash)
        )
        self.conn.commit()

    def get_block_hash(self, chain: str, height: int):
        """Lookup a stored block hash. Returns hash string or None."""
        row = self.conn.execute(
            "SELECT block_hash FROM block_hashes WHERE chain = ? AND height = ?",
            (chain, height)
        ).fetchone()
        return row["block_hash"] if row else None

    def prune_block_hashes(self, chain: str, keep_last: int = 200):
        """Remove old block hashes, keeping the most recent N."""
        self.conn.execute(
            """DELETE FROM block_hashes
               WHERE chain = ? AND height < (
                   SELECT MAX(height) - ? FROM block_hashes WHERE chain = ?
               )""",
            (chain, keep_last, chain)
        )
        self.conn.commit()

    def get_minted_deposits_above_height(self, chain: str, min_height: int):
        """Get deposits that were already minted but are at or above min_height.
        Used to detect backing invariant breach during reorgs."""
        return self.conn.execute(
            """SELECT * FROM deposits
               WHERE chain = ? AND block_height >= ? AND status = 'minted'""",
            (chain, min_height)
        ).fetchall()

    # ── Invariant checks ────────────────────────────────────────────

    def record_invariant_check(self, chain: str, native_balance: int,
                               wrapped_supply: int, inflight: int,
                               status: str, delta: int):
        """Record a backing invariant check result."""
        self.conn.execute(
            """INSERT INTO invariant_checks
               (chain, native_balance, wrapped_supply, inflight_withdrawals,
                status, delta)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (chain, native_balance, wrapped_supply, inflight, status, delta)
        )
        self.conn.commit()

    def get_inflight_withdrawal_total(self, chain: str) -> int:
        """Sum of amounts for withdrawals in sending/confirmed state."""
        row = self.conn.execute(
            """SELECT COALESCE(SUM(amount), 0) as total FROM withdrawals
               WHERE chain = ? AND status IN ('confirmed', 'sending')""",
            (chain,)
        ).fetchone()
        return row["total"]

    # ── Stats ────────────────────────────────────────────────────────

    def get_stats(self):
        """Get summary statistics for health monitoring."""
        stats = {}
        for status in ('pending', 'confirmed', 'minted', 'failed', 'reorged'):
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM deposits WHERE status = ?", (status,)
            ).fetchone()
            stats[f"deposits_{status}"] = row["cnt"]

        # Count deposits deferred due to cap (failed with "Mint tx reverted")
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM deposits "
            "WHERE status = 'failed' AND error_msg = 'Mint tx reverted'"
        ).fetchone()
        stats["deposits_cap_deferred"] = row["cnt"]

        for status in ('pending', 'confirmed', 'sending', 'sent', 'completed', 'failed'):
            row = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM withdrawals WHERE status = ?", (status,)
            ).fetchone()
            stats[f"withdrawals_{status}"] = row["cnt"]

        for chain in ('dil', 'dilv'):
            stats[f"daily_minted_{chain}"] = self.get_daily_minted(chain)

        return stats

    def close(self):
        self.conn.close()
