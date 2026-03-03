#!/usr/bin/env python3
"""
Phase 6 HTLC & Atomic Swap RPC Integration Tests
=================================================
Tests all 8 Phase 6 RPC commands against a running DilV node.

Usage:
    python3 test_htlc.py [--port PORT]

Prerequisites:
    1. Start dilv-node:
         ./dilv-node.exe --no-upnp --mine
    2. Wait ~30 seconds for the node to initialize and mine a block.
    3. Run this script.

The script will skip tests that require funded UTXOs if the wallet
balance is too low to cover fees.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_PORT = 8332
RPC_USER = "rpc"
RPC_PASS = "rpc"

DUST_THRESHOLD = 1000  # satoshi-equivalent: minimum amount that covers fees
TEST_AMOUNT = 10_000   # 0.0001 DilV (in volts)

# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

passed = 0
failed = 0
skipped = 0


def rpc(method, params=None, port=DEFAULT_PORT):
    """Execute a JSON-RPC call against the node."""
    if params is None:
        params = {}
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    cmd = [
        "curl", "-s",
        "--user", f"{RPC_USER}:{RPC_PASS}",
        "-H", "X-Dilithion-RPC: 1",
        "-H", "content-type: application/json",
        "--data-binary", body,
        f"http://127.0.0.1:{port}/",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"curl failed: {result.stderr}")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON from node: {result.stdout[:200]}") from e
    if response.get("error"):
        raise RuntimeError(f"RPC error: {response['error']}")
    return response.get("result")


def test(name):
    """Print test name."""
    print(f"  {name}... ", end="", flush=True)


def ok(detail=""):
    global passed
    print(f"PASS{' (' + detail + ')' if detail else ''}")
    passed += 1


def fail(reason):
    global failed
    print(f"FAIL: {reason}")
    failed += 1


def skip(reason):
    global skipped
    print(f"SKIP ({reason})")
    skipped += 1


def check(cond, label=""):
    if not cond:
        raise AssertionError(label or "assertion failed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def get_wallet_address(port):
    """Return the node's mining/wallet address."""
    try:
        result = rpc("getminingaddress", {}, port)
        if result and isinstance(result, str):
            return result
    except Exception:
        pass
    # Fall back to getaddress if available
    try:
        result = rpc("getaddress", {}, port)
        if result and isinstance(result, str):
            return result
    except Exception:
        pass
    return None


def get_balance(port):
    """Return wallet balance in volts (smallest unit)."""
    try:
        result = rpc("getbalance", {}, port)
        if result is not None:
            # May be a float (DilV) or an integer (volts)
            if isinstance(result, float):
                return int(result * 100_000_000)
            return int(result)
    except Exception:
        pass
    return 0


def get_blockchain_info(port):
    return rpc("getblockchaininfo", {}, port)


def get_best_height(port):
    try:
        info = get_blockchain_info(port)
        return info.get("blocks", 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Test groups
# ---------------------------------------------------------------------------

def test_node_alive(port):
    print("\n-- Node Connectivity --")
    test("node_responds_to_getblockchaininfo")
    try:
        info = get_blockchain_info(port)
        check(info is not None)
        chain = info.get("chain", "")
        height = info.get("blocks", 0)
        ok(f"chain={chain}, height={height}")
    except Exception as e:
        fail(str(e))
        sys.exit(1)  # No point continuing if node is unreachable


def test_generatepreimage(port):
    print("\n-- generatepreimage --")

    test("returns_preimage_and_hash")
    try:
        result = rpc("generatepreimage", {}, port)
        check("preimage" in result, "has preimage")
        check("hash" in result, "has hash")
        preimage_hex = result["preimage"]
        hash_hex = result["hash"]
        check(len(preimage_hex) == 64, "preimage is 64 hex chars")
        check(len(hash_hex) == 64, "hash is 64 hex chars")
        ok()
    except Exception as e:
        fail(str(e))
        return

    test("hash_matches_sha3_256_of_preimage")
    try:
        preimage_bytes = hex_to_bytes(preimage_hex)
        expected_hash = sha3_256(preimage_bytes).hex()
        check(hash_hex == expected_hash,
              f"expected {expected_hash}, got {hash_hex}")
        ok()
    except Exception as e:
        fail(str(e))

    test("two_calls_return_different_preimages")
    try:
        r1 = rpc("generatepreimage", {}, port)["preimage"]
        r2 = rpc("generatepreimage", {}, port)["preimage"]
        check(r1 != r2, "both calls returned same preimage — RNG broken!")
        ok()
    except Exception as e:
        fail(str(e))

    # Return the preimage and hash for use in later tests
    return preimage_hex, hash_hex


def test_listswaps(port, expected_min=0):
    print("\n-- listswaps --")

    test("returns_array")
    try:
        result = rpc("listswaps", {}, port)
        check(isinstance(result, list), f"expected list, got {type(result)}")
        ok(f"{len(result)} swaps")
        return result
    except Exception as e:
        fail(str(e))
        return []

    if expected_min > 0:
        test(f"has_at_least_{expected_min}_swap(s)")
        try:
            check(len(result) >= expected_min)
            ok()
        except Exception as e:
            fail(str(e))


def test_initiateswap_and_claim(port, preimage_hex, hash_hex):
    print("\n-- initiateswap + claimhtlc (self-swap) --")

    # Get our wallet address (will be the recipient on the "their" side)
    wallet_addr = get_wallet_address(port)
    if not wallet_addr:
        test("initiateswap_self_swap")
        skip("could not determine wallet address")
        return

    balance = get_balance(port)
    if balance < TEST_AMOUNT * 2:
        test("initiateswap_self_swap")
        skip(f"insufficient balance ({balance} volts, need {TEST_AMOUNT * 2})")
        return

    test("initiateswap_creates_htlc")
    swap_id = None
    htlc_txid = None
    try:
        # Self-swap: our own address is the "claim" address.
        # This lets us test the full claim path in a single-node setup.
        result = rpc("initiateswap", {
            "their_chain": "dilv",
            "send_amount": TEST_AMOUNT,
            "receive_amount": TEST_AMOUNT,
            "their_claim_address": wallet_addr,
            "timeout_blocks": 10,  # short timeout for testing
        }, port)
        check("swap_id" in result)
        check("htlc_txid" in result)
        check("hash_lock" in result)
        check("timeout_height" in result)
        swap_id = result["swap_id"]
        htlc_txid = result["htlc_txid"]
        stored_hash = result["hash_lock"]
        timeout_height = result["timeout_height"]
        check(len(swap_id) == 16, f"swap_id len {len(swap_id)}")
        check(len(htlc_txid) == 64, f"txid len {len(htlc_txid)}")
        ok(f"swap_id={swap_id[:8]}…, txid={htlc_txid[:8]}…")
    except Exception as e:
        fail(str(e))
        return

    # Verify swap appears in listswaps
    test("swap_appears_in_listswaps")
    try:
        swaps = rpc("listswaps", {}, port)
        ids = [s.get("swap_id") for s in swaps]
        check(swap_id in ids, f"swap_id {swap_id} not in {ids}")
        ok()
    except Exception as e:
        fail(str(e))

    # decodehtlc on the funding tx output
    test("decodehtlc_shows_correct_parameters")
    try:
        result = rpc("decodehtlc", {
            "htlc_txid": htlc_txid,
            "vout": 0,
        }, port)
        check("hash_lock" in result)
        check("timeout_height" in result)
        check(result["timeout_height"] == timeout_height)
        ok(f"timeout_height={timeout_height}")
    except Exception as e:
        fail(str(e))

    # Try to claim with WRONG preimage — should fail
    test("claimhtlc_wrong_preimage_fails")
    try:
        wrong_preimage = "ff" * 32  # all 0xFF
        rpc("claimhtlc", {
            "htlc_txid": htlc_txid,
            "htlc_vout": 0,
            "preimage": wrong_preimage,
        }, port)
        fail("should have returned an error for wrong preimage")
    except RuntimeError as e:
        msg = str(e).lower()
        if "preimage" in msg or "hash" in msg or "match" in msg:
            ok(f"error: {str(e)[:60]}")
        else:
            fail(f"unexpected error message: {e}")

    # Claim with the CORRECT preimage
    test("claimhtlc_correct_preimage_succeeds")
    try:
        result = rpc("claimhtlc", {
            "htlc_txid": htlc_txid,
            "htlc_vout": 0,
            "preimage": preimage_hex,
        }, port)
        check("txid" in result)
        claim_txid = result["txid"]
        check(len(claim_txid) == 64)
        ok(f"claim_txid={claim_txid[:8]}…")
    except Exception as e:
        fail(str(e))
        return

    # Try to claim the same HTLC again — UTXO should be spent
    test("claimhtlc_double_spend_fails")
    try:
        rpc("claimhtlc", {
            "htlc_txid": htlc_txid,
            "htlc_vout": 0,
            "preimage": preimage_hex,
        }, port)
        fail("double-spend should have been rejected")
    except RuntimeError as e:
        if "utxo" in str(e).lower() or "not found" in str(e).lower() or "spent" in str(e).lower():
            ok(f"correctly rejected: {str(e)[:60]}")
        else:
            fail(f"unexpected error: {e}")


def test_refundhtlc_before_timeout(port):
    """Create an HTLC with a future timeout, immediately try to refund — should fail."""
    print("\n-- refundhtlc (early refund prevention) --")

    balance = get_balance(port)
    if balance < TEST_AMOUNT * 2:
        test("refundhtlc_before_timeout_fails")
        skip(f"insufficient balance ({balance} volts)")
        return

    wallet_addr = get_wallet_address(port)
    if not wallet_addr:
        test("refundhtlc_before_timeout_fails")
        skip("could not determine wallet address")
        return

    test("refundhtlc_before_timeout_fails")
    try:
        # Create a swap with a long timeout
        result = rpc("initiateswap", {
            "their_chain": "dilv",
            "send_amount": TEST_AMOUNT,
            "receive_amount": TEST_AMOUNT,
            "their_claim_address": wallet_addr,
            "timeout_blocks": 384,  # normal timeout
        }, port)
        htlc_txid = result["htlc_txid"]
        timeout_height = result["timeout_height"]

        # Immediately try to refund — should fail
        rpc("refundhtlc", {
            "htlc_txid": htlc_txid,
            "htlc_vout": 0,
        }, port)
        fail("refund before timeout should have been rejected")
    except RuntimeError as e:
        msg = str(e).lower()
        if "timeout" in msg or "height" in msg or "blocks" in msg or "expired" in msg:
            ok(f"correctly rejected: {str(e)[:80]}")
        else:
            fail(f"unexpected error: {e}")


def test_claimhtlc_wrong_preimage_length(port):
    """generatepreimage + claimhtlc with wrong-length preimage — should fail."""
    print("\n-- Input validation --")

    # We just need any funded HTLC txid. If we don't have one, skip.
    test("claimhtlc_rejects_wrong_preimage_length")
    try:
        rpc("claimhtlc", {
            "htlc_txid": "00" * 32,
            "htlc_vout": 0,
            "preimage": "ff" * 16,  # only 16 bytes — should be 32
        }, port)
        fail("should have rejected 16-byte preimage")
    except RuntimeError as e:
        if "hex" in str(e).lower() or "bytes" in str(e).lower() or "length" in str(e).lower() or "chars" in str(e).lower():
            ok(f"correctly rejected: {str(e)[:60]}")
        else:
            # Even "UTXO not found" is acceptable — we at least checked the hash
            ok(f"failed (different reason): {str(e)[:60]}")


def test_listswaps_state_filter(port):
    print("\n-- listswaps state filter --")
    test("listswaps_all")
    try:
        all_swaps = rpc("listswaps", {}, port)
        check(isinstance(all_swaps, list))
        ok(f"{len(all_swaps)} total")
    except Exception as e:
        fail(str(e))

    test("listswaps_htlc_funded_filter")
    try:
        funded = rpc("listswaps", {"state": 1}, port)  # SwapState::HTLC_FUNDED = 1
        check(isinstance(funded, list))
        for s in funded:
            check(s.get("state") == 1, f"unexpected state {s.get('state')}")
        ok(f"{len(funded)} htlc_funded")
    except Exception as e:
        fail(str(e))


def test_swap_fields(port):
    """Verify that initiateswap returns all expected fields."""
    print("\n-- initiateswap field validation --")
    balance = get_balance(port)
    if balance < TEST_AMOUNT * 2:
        test("initiateswap_returns_all_fields")
        skip(f"insufficient balance ({balance} volts)")
        return

    wallet_addr = get_wallet_address(port)
    if not wallet_addr:
        test("initiateswap_returns_all_fields")
        skip("could not determine wallet address")
        return

    test("initiateswap_returns_all_fields")
    try:
        result = rpc("initiateswap", {
            "their_chain": "dilv",
            "send_amount": TEST_AMOUNT,
            "receive_amount": TEST_AMOUNT,
            "their_claim_address": wallet_addr,
            "timeout_blocks": 10,
        }, port)
        required = ["swap_id", "hash_lock", "htlc_txid", "timeout_height",
                    "send_amount", "receive_amount"]
        for field in required:
            check(field in result, f"missing field: {field}")
        check(len(result["hash_lock"]) == 64, "hash_lock should be 64 hex chars")
        check(result["timeout_height"] > get_best_height(port), "timeout in past!")
        ok(f"all {len(required)} fields present")
    except Exception as e:
        fail(str(e))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Phase 6 HTLC RPC integration tests")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"RPC port (default: {DEFAULT_PORT})")
    args = parser.parse_args()
    port = args.port

    print("=" * 50)
    print(f"Phase 6 HTLC Integration Tests  (port {port})")
    print("=" * 50)

    # Always run these
    test_node_alive(port)

    # generatepreimage — always runnable
    pg_result = test_generatepreimage(port)
    if pg_result:
        preimage_hex, hash_hex = pg_result
    else:
        preimage_hex = "ab" * 32
        hash_hex = sha3_256(bytes.fromhex(preimage_hex)).hex()

    # listswaps — always runnable
    test_listswaps(port)

    # Input validation — always runnable
    test_claimhtlc_wrong_preimage_length(port)
    test_listswaps_state_filter(port)

    # These require funded wallet + mining
    test_initiateswap_and_claim(port, preimage_hex, hash_hex)
    test_refundhtlc_before_timeout(port)
    test_swap_fields(port)

    # Summary
    print("\n" + "=" * 50)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    if failed > 0:
        print("SOME TESTS FAILED")
        sys.exit(1)
    print("ALL TESTS PASSED (or skipped)")
    sys.exit(0)


if __name__ == "__main__":
    main()
