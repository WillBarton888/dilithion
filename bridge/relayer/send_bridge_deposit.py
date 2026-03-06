"""Send a bridge deposit transaction with OP_RETURN metadata.

Constructs a raw transaction that pays the bridge address and includes
an OP_RETURN output encoding the user's Base address for wToken minting.
"""

import struct
import hashlib
import sys
import json

# We need SHA3-256, which Python's hashlib supports
def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


# ── Base58 codec (matching Dilithion's SHA3-256 checksum) ──────────────

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_decode(s: str) -> bytes:
    """Decode a Base58 string to bytes."""
    n = 0
    for c in s:
        n = n * 58 + BASE58_ALPHABET.index(c.encode())
    # Convert to bytes
    result = []
    while n > 0:
        result.append(n % 256)
        n //= 256
    # Add leading zeros
    for c in s:
        if c == '1':
            result.append(0)
        else:
            break
    return bytes(reversed(result))

def base58check_decode(s: str) -> bytes:
    """Decode Base58Check (SHA3-256 checksum) and return payload (version + hash)."""
    raw = base58_decode(s)
    payload, checksum = raw[:-4], raw[-4:]
    # Verify checksum: double SHA3-256
    expected = sha3_256(sha3_256(payload))[:4]
    if checksum != expected:
        raise ValueError(f"Base58Check checksum mismatch: {checksum.hex()} != {expected.hex()}")
    return payload


# ── Transaction serialization helpers ──────────────────────────────────

def compact_size(n: int) -> bytes:
    if n < 253:
        return struct.pack('<B', n)
    elif n <= 0xFFFF:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def uint32_le(n: int) -> bytes:
    return struct.pack('<I', n)

def uint64_le(n: int) -> bytes:
    return struct.pack('<Q', n)


def build_p2pkh_script(pubkey_hash: bytes) -> bytes:
    """Build P2PKH scriptPubKey: OP_DUP OP_HASH160 <len> <hash> OP_EQUALVERIFY OP_CHECKSIG"""
    return bytes([0x76, 0xa9, len(pubkey_hash)]) + pubkey_hash + bytes([0x88, 0xac])


def build_op_return_script(data: bytes) -> bytes:
    """Build OP_RETURN scriptPubKey: OP_RETURN <push_len> <data>"""
    # OP_RETURN (0x6a) + push opcode + data
    if len(data) < 76:
        return bytes([0x6a, len(data)]) + data
    else:
        raise ValueError("OP_RETURN data too large")


def build_raw_transaction(
    inputs: list,
    bridge_address: str,
    deposit_amount_sats: int,
    change_address: str,
    change_amount_sats: int,
    op_return_data: bytes,
    op_return_value: int = 50000,
) -> bytes:
    """Build an unsigned raw transaction with multiple inputs, bridge deposit + OP_RETURN + change.

    inputs: list of (txid_hex, vout) tuples
    """

    tx = bytearray()

    # Version (1)
    tx += uint32_le(1)

    # Input count
    tx += compact_size(len(inputs))

    for txid_hex, vout in inputs:
        # Input: prevout hash (reversed for internal byte order)
        txid_bytes = bytes.fromhex(txid_hex)
        tx += bytes(reversed(txid_bytes))
        # Input: prevout index (4 bytes)
        tx += uint32_le(vout)
        # Input: scriptSig (empty for unsigned tx)
        tx += compact_size(0)
        # Input: sequence
        tx += uint32_le(0xFFFFFFFF)

    # Output count (3: bridge payment + OP_RETURN + change)
    tx += compact_size(3)

    # Output 1: Payment to bridge address
    bridge_payload = base58check_decode(bridge_address)
    bridge_pubkey_hash = bridge_payload[1:]
    bridge_script = build_p2pkh_script(bridge_pubkey_hash)

    tx += uint64_le(deposit_amount_sats)
    tx += compact_size(len(bridge_script))
    tx += bridge_script

    # Output 2: OP_RETURN with bridge metadata
    op_return_script = build_op_return_script(op_return_data)
    tx += uint64_le(op_return_value)
    tx += compact_size(len(op_return_script))
    tx += op_return_script

    # Output 3: Change back to wallet
    change_payload = base58check_decode(change_address)
    change_pubkey_hash = change_payload[1:]
    change_script = build_p2pkh_script(change_pubkey_hash)

    tx += uint64_le(change_amount_sats)
    tx += compact_size(len(change_script))
    tx += change_script

    # Locktime
    tx += uint32_le(0)

    return bytes(tx)


def main():
    import argparse
    from dilithion_rpc import DilithionRPC

    parser = argparse.ArgumentParser(description="Send bridge deposit with OP_RETURN")
    parser.add_argument("--chain", choices=["dil", "dilv"], required=True)
    parser.add_argument("--amount", type=float, required=True, help="Amount in coins")
    parser.add_argument("--base-address", required=True, help="Base L2 destination (0x...)")
    parser.add_argument("--auto", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--max-inputs", type=int, default=50, help="Max UTXOs to use (default: 50)")
    args = parser.parse_args()

    CHAIN_CONFIG = {
        "dil":  {"bridge": "DPW8h76TAGwj569LgbdLCAFUcgixMuoBWc", "rpc_port": 8332, "coin": "DIL"},
        "dilv": {"bridge": "DESyLBcZYDU1jrE2o1GuQkdiuiwk2An6Sn", "rpc_port": 9332, "coin": "DilV"},
    }
    cfg = CHAIN_CONFIG[args.chain]

    BRIDGE_ADDRESS = cfg["bridge"]
    BASE_ADDRESS = args.base_address
    DEPOSIT_AMOUNT_COINS = args.amount
    COIN = cfg["coin"]

    DEPOSIT_AMOUNT_SATS = int(DEPOSIT_AMOUNT_COINS * 1e8)
    OP_RETURN_VALUE = 50000  # 0.0005 coins (burned, unspendable)
    # Fee calculated dynamically after input selection (see below)

    # Connect to node
    rpc = DilithionRPC(f"http://127.0.0.1:{cfg['rpc_port']}", "rpc", "rpc", args.chain)

    # Find suitable UTXOs (select largest first until we have enough)
    utxos = rpc._call("listunspent")
    print(f"Found {len(utxos)} UTXOs")

    # Convert amounts and sort by size (largest first)
    # IMPORTANT: Exclude UTXOs at the bridge address to avoid spending previous deposits
    for utxo in utxos:
        amount = utxo["amount"]
        if isinstance(amount, float) and amount < 10000:
            utxo["amount_sats"] = int(round(amount * 1e8))
        else:
            utxo["amount_sats"] = int(amount)
    utxos = [u for u in utxos if u.get("address") != BRIDGE_ADDRESS]
    utxos.sort(key=lambda u: u["amount_sats"], reverse=True)
    print(f"  ({len(utxos)} UTXOs after excluding bridge address)")

    # Select UTXOs until we have enough (use conservative fee estimate for selection)
    FEE_RATE = 6  # volts per byte (min relay fee is 5, use 6 for safety)
    est_fee_sats = args.max_inputs * 5400 * FEE_RATE  # ~5400 bytes per Dilithium-signed input
    needed = DEPOSIT_AMOUNT_SATS + est_fee_sats + OP_RETURN_VALUE + 1000  # extra buffer
    selected = []
    total_sats = 0
    for utxo in utxos:
        if len(selected) >= args.max_inputs:
            break
        selected.append(utxo)
        total_sats += utxo["amount_sats"]
        if total_sats >= needed:
            break

    # Recalculate fee based on actual number of inputs selected
    # Each Dilithium-signed input is ~5,324 bytes, plus ~200 bytes overhead
    est_signed_size = len(selected) * 5400 + 200
    FEE_SATS = est_signed_size * FEE_RATE
    FEE_COINS = FEE_SATS / 1e8
    actual_needed = DEPOSIT_AMOUNT_SATS + FEE_SATS + OP_RETURN_VALUE

    if total_sats < actual_needed:
        print(f"ERROR: Insufficient funds! Have {total_sats/1e8:.8f}, need {actual_needed/1e8:.8f} {COIN}")
        print(f"  Selected {len(selected)} UTXOs (max {args.max_inputs})")
        print(f"  Estimated fee: {FEE_COINS:.8f} {COIN} ({est_signed_size} bytes @ {FEE_RATE} volts/byte)")
        sys.exit(1)

    print(f"\nSelected {len(selected)} UTXOs totaling {total_sats/1e8:.8f} {COIN}")
    for i, u in enumerate(selected[:5]):
        print(f"  [{i+1}] {u['txid'][:16]}... vout={u['vout']} amount={u['amount_sats']/1e8:.8f}")
    if len(selected) > 5:
        print(f"  ... and {len(selected)-5} more")

    # Use a non-bridge address for change (first selected UTXO's address is safe
    # since we already excluded bridge address UTXOs from selection)
    change_address = selected[0]["address"]
    if change_address == BRIDGE_ADDRESS:
        print("ERROR: Change address is the bridge address! This should not happen.")
        sys.exit(1)
    change_sats = total_sats - DEPOSIT_AMOUNT_SATS - OP_RETURN_VALUE - FEE_SATS

    print(f"\nTransaction plan:")
    print(f"  Deposit: {DEPOSIT_AMOUNT_COINS} {COIN} -> {BRIDGE_ADDRESS}")
    print(f"  OP_RETURN: DBRG + {BASE_ADDRESS}")
    print(f"  Change: {change_sats / 1e8:.8f} {COIN} -> {change_address}")
    print(f"  Fee: {FEE_COINS:.8f} {COIN} (est {est_signed_size/1024:.0f} KB @ {FEE_RATE} volts/byte)")
    print(f"  Inputs: {len(selected)}")

    # Build OP_RETURN data: DBRG tag (4 bytes) + Base address (20 bytes)
    bridge_tag = b"DBRG"
    base_addr_bytes = bytes.fromhex(BASE_ADDRESS[2:])  # Remove 0x prefix
    op_return_data = bridge_tag + base_addr_bytes
    print(f"\n  OP_RETURN data ({len(op_return_data)} bytes): {op_return_data.hex()}")

    # Build raw transaction with multiple inputs
    input_list = [(u["txid"], u["vout"]) for u in selected]
    raw_tx = build_raw_transaction(
        inputs=input_list,
        bridge_address=BRIDGE_ADDRESS,
        deposit_amount_sats=DEPOSIT_AMOUNT_SATS,
        change_address=change_address,
        change_amount_sats=change_sats,
        op_return_data=op_return_data,
        op_return_value=OP_RETURN_VALUE,
    )

    raw_hex = raw_tx.hex()
    print(f"\nRaw unsigned transaction ({len(raw_tx)} bytes):")
    print(f"  {raw_hex[:80]}...")

    # Sign the transaction (longer timeout for multi-input Dilithium sigs)
    print(f"\nSigning transaction ({len(selected)} inputs)...")
    sign_result = rpc._call("signrawtransaction", {"hex": raw_hex}, timeout=120)
    print(f"  Sign result: complete={sign_result.get('complete')}")

    if not sign_result.get("complete"):
        print("ERROR: Transaction signing failed!")
        print(f"  Result: {json.dumps(sign_result, indent=2)}")
        sys.exit(1)

    signed_hex = sign_result["hex"]
    signed_size = len(signed_hex) // 2
    print(f"  Signed tx size: {signed_size} bytes ({signed_size/1024:.1f} KB)")

    if signed_size > 1000000:
        print(f"ERROR: Signed tx exceeds 1MB limit! Use fewer inputs (--max-inputs).")
        sys.exit(1)

    # Ask for confirmation before broadcasting
    print(f"\n{'='*60}")
    print(f"READY TO BROADCAST bridge deposit transaction:")
    print(f"  Amount: {DEPOSIT_AMOUNT_COINS} {COIN}")
    print(f"  To: {BRIDGE_ADDRESS}")
    print(f"  Base address: {BASE_ADDRESS}")
    print(f"  Fee: {FEE_COINS} {COIN}")
    print(f"  Tx size: {signed_size/1024:.1f} KB ({len(selected)} inputs)")
    print(f"{'='*60}")

    if not args.auto:
        confirm = input("\nType 'yes' to broadcast: ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            sys.exit(0)

    # Broadcast (longer timeout for validation of multi-input tx)
    print("\nBroadcasting transaction...")
    result = rpc._call("sendrawtransaction", {"hex": signed_hex}, timeout=120)
    print(f"\nTransaction broadcast! Result: {result}")


if __name__ == "__main__":
    main()
