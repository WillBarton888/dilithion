"""Thin JSON-RPC client for Dilithion nodes (DIL and DilV)."""

import json
import logging
import socket

logger = logging.getLogger(__name__)


class DilithionRPC:
    """Minimal JSON-RPC 2.0 client for Dilithion/DilV nodes.

    Uses raw sockets for reliable operation on Windows, and object-style
    params as required by Dilithion's RPC server.
    """

    def __init__(self, url: str, user: str, password: str, chain: str = "dil"):
        self.url = url
        self.chain = chain
        self._id = 0

        from urllib.parse import urlparse
        parsed = urlparse(url)
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or 8332

        import base64
        cred = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._auth_header = f"Basic {cred}"

    def _call(self, method: str, params=None, timeout: int = 30):
        """Make a JSON-RPC 2.0 call with a fresh socket each time."""
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params if params is not None else {},
        }).encode()

        request = (
            f"POST / HTTP/1.0\r\n"
            f"Host: {self._host}:{self._port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Authorization: {self._auth_header}\r\n"
            f"X-Dilithion-RPC: 1\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + payload

        try:
            sock = socket.create_connection((self._host, self._port), timeout=timeout)
            sock.sendall(request)

            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except ConnectionResetError:
                    break  # Windows: server closesocket() causes reset
            sock.close()

            raw = b"".join(chunks).decode()
        except Exception as e:
            logger.error(f"[{self.chain}] RPC error calling {method}: {e}")
            raise

        header_end = raw.find("\r\n\r\n")
        if header_end == -1:
            raise RuntimeError(f"[{self.chain}] RPC {method}: malformed response")

        status_line = raw[:raw.find("\r\n")]
        body = raw[header_end + 4:]

        if "200" not in status_line:
            raise RuntimeError(
                f"[{self.chain}] RPC {method}: {status_line} — {body[:200]}"
            )

        result = json.loads(body)

        if result.get("error"):
            raise RuntimeError(
                f"[{self.chain}] RPC {method} error: {result['error']}"
            )

        return result.get("result")

    # ── Block queries ────────────────────────────────────────────────

    def get_block_count(self) -> int:
        """Get current block height."""
        return self._call("getblockcount")

    def get_block_hash(self, height: int) -> str:
        """Get block hash at given height."""
        result = self._call("getblockhash", {"height": height})
        # Server returns {"blockhash": "..."} — unwrap
        if isinstance(result, dict):
            return result.get("blockhash", str(result))
        return result

    def get_block(self, block_hash: str, verbosity: int = 2) -> dict:
        """Get block with transactions (verbosity=2 for full tx details)."""
        return self._call("getblock", {"hash": block_hash, "verbosity": verbosity})

    def get_blockchain_info(self) -> dict:
        """Get chain status (height, chain name, etc.)."""
        return self._call("getblockchaininfo")

    # ── Transaction queries ──────────────────────────────────────────

    def get_raw_transaction(self, txid: str) -> dict:
        """Get decoded transaction by txid."""
        return self._call("getrawtransaction", {"txid": txid, "verbosity": 1})

    def get_tx_out(self, txid: str, vout: int) -> dict:
        """Get UTXO info for a specific output."""
        return self._call("gettxout", {"txid": txid, "n": vout})

    # ── Wallet operations ────────────────────────────────────────────

    def send_to_address(self, address: str, amount: float) -> str:
        """Send coins to an address. Returns txid string."""
        result = self._call("sendtoaddress", {"address": address, "amount": amount})
        # RPC returns {"txid": "..."} dict — unwrap to plain string
        if isinstance(result, dict):
            return result.get("txid", str(result))
        return str(result)

    def get_balance(self) -> float:
        """Get wallet balance in coins."""
        result = self._call("getbalance")
        if isinstance(result, dict):
            return float(result.get("balance", 0.0))
        return float(result)

    def list_transactions(self, count: int = 50) -> list:
        """List recent wallet transactions for reconciliation."""
        result = self._call("listtransactions", {"count": count})
        if isinstance(result, dict):
            return result.get("transactions", [])
        return result if isinstance(result, list) else []

    def get_transaction(self, txid: str) -> dict:
        """Get wallet transaction details by txid. Returns dict or None."""
        try:
            return self._call("gettransaction", {"txid": txid})
        except Exception:
            return None

    def validate_address(self, address: str) -> bool:
        """Validate a native chain address via the node's RPC.
        Returns True if the address is valid (base58check passes)."""
        try:
            result = self._call("validateaddress", {"address": address})
            if isinstance(result, dict):
                return result.get("isvalid", False)
            return False
        except Exception:
            return False

    def rescan_wallet(self) -> dict:
        """Rescan blockchain for wallet transactions."""
        return self._call("rescanblockchain")

    # ── Utility ──────────────────────────────────────────────────────

    def is_connected(self) -> bool:
        """Check if we can reach the node."""
        try:
            self.get_blockchain_info()
            return True
        except Exception:
            return False
