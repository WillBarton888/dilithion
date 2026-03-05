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
    utxo_txid: str,
    utxo_vout: int,
    bridge_address: str,
    deposit_amount_sats: int,
    change_address: str,
    change_amount_sats: int,
    op_return_data: bytes,
    op_return_value: int = 50000,
) -> bytes:
    """Build an unsigned raw transaction with bridge deposit + OP_RETURN + change."""

    tx = bytearray()

    # Version (1)
    tx += uint32_le(1)

    # Input count
    tx += compact_size(1)

    # Input: prevout hash (32 bytes, internal byte order = reversed hex)
    txid_bytes = bytes.fromhex(utxo_txid)
    # In Bitcoin serialization, txid is stored in internal byte order (reversed)
    # But Dilithion might store it as-is. Let me check...
    # The UTXO txid from listunspent is the display hex. In Bitcoin, the hash
    # stored in prevout is the actual hash bytes (which displays reversed).
    # Let's try reversed first (Bitcoin convention).
    tx += bytes(reversed(txid_bytes))

    # Input: prevout index (4 bytes)
    tx += uint32_le(utxo_vout)

    # Input: scriptSig (empty for unsigned tx)
    tx += compact_size(0)

    # Input: sequence
    tx += uint32_le(0xFFFFFFFF)

    # Output count (3: bridge payment + OP_RETURN + change)
    tx += compact_size(3)

    # Output 1: Payment to bridge address
    bridge_payload = base58check_decode(bridge_address)
    bridge_version = bridge_payload[0]
    bridge_pubkey_hash = bridge_payload[1:]
    bridge_script = build_p2pkh_script(bridge_pubkey_hash)

    tx += uint64_le(deposit_amount_sats)
    tx += compact_size(len(bridge_script))
    tx += bridge_script

    # Output 2: OP_RETURN with bridge metadata
    # Use dust-threshold value (50000 ions) instead of zero to pass consensus
    # on nodes that haven't yet upgraded to the OP_RETURN exemption
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
    from dilithion_rpc import DilithionRPC

    # Configuration
    BRIDGE_ADDRESS = "DUJzPMZYD1H1Dvvy8Wo3eQx8Phy99Baemo"
    BASE_ADDRESS = "0x758F0063417E13Ab20C360454AA95C3dD5e7ffB7"
    DEPOSIT_AMOUNT_DIL = 1.0  # 1 DIL test deposit
    FEE_DIL = 0.001  # 0.001 DIL fee

    DEPOSIT_AMOUNT_SATS = int(DEPOSIT_AMOUNT_DIL * 1e8)
    FEE_SATS = int(FEE_DIL * 1e8)

    # Connect to node
    rpc = DilithionRPC("http://127.0.0.1:8332", "rpc", "rpc", "dil")

    # Find a suitable UTXO
    utxos = rpc._call("listunspent")
    print(f"Found {len(utxos)} UTXOs")

    # Find one large enough (skip UTXOs already spent in mempool)
    SKIP_TXIDS = {"856f147a8c327ad95a903b03511adeac45670506f8d39dcd4926b3a66b598d00"}
    selected_utxo = None
    for utxo in utxos:
        if utxo["txid"] in SKIP_TXIDS:
            continue
        amount = utxo["amount"]
        # Amount might be in DIL (float) or satoshis (int)
        if isinstance(amount, float) and amount < 10000:
            amount_sats = int(round(amount * 1e8))
        else:
            amount_sats = int(amount)

        needed = DEPOSIT_AMOUNT_SATS + FEE_SATS + 50000 + 1000  # deposit + fee + OP_RETURN + dust
        if amount_sats >= needed:
            selected_utxo = utxo
            selected_utxo["amount_sats"] = amount_sats
            break

    if not selected_utxo:
        print("ERROR: No UTXO large enough found!")
        sys.exit(1)

    print(f"\nSelected UTXO:")
    print(f"  txid: {selected_utxo['txid']}")
    print(f"  vout: {selected_utxo['vout']}")
    print(f"  amount: {selected_utxo['amount']} DIL ({selected_utxo['amount_sats']} sats)")
    print(f"  address: {selected_utxo['address']}")

    change_address = selected_utxo["address"]  # Send change back to same address
    OP_RETURN_VALUE = 50000  # 0.0005 DIL dust threshold (burned, unspendable)
    change_sats = selected_utxo["amount_sats"] - DEPOSIT_AMOUNT_SATS - OP_RETURN_VALUE - FEE_SATS

    print(f"\nTransaction plan:")
    print(f"  Deposit: {DEPOSIT_AMOUNT_DIL} DIL -> {BRIDGE_ADDRESS}")
    print(f"  OP_RETURN: DBRG + {BASE_ADDRESS}")
    print(f"  Change: {change_sats / 1e8:.8f} DIL -> {change_address}")
    print(f"  Fee: {FEE_DIL} DIL")

    # Build OP_RETURN data: DBRG tag (4 bytes) + Base address (20 bytes)
    bridge_tag = b"DBRG"
    base_addr_bytes = bytes.fromhex(BASE_ADDRESS[2:])  # Remove 0x prefix
    op_return_data = bridge_tag + base_addr_bytes
    print(f"\n  OP_RETURN data ({len(op_return_data)} bytes): {op_return_data.hex()}")

    # Build raw transaction
    raw_tx = build_raw_transaction(
        utxo_txid=selected_utxo["txid"],
        utxo_vout=selected_utxo["vout"],
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

    # Sign the transaction
    print("\nSigning transaction...")
    sign_result = rpc._call("signrawtransaction", {"hex": raw_hex})
    print(f"  Sign result: complete={sign_result.get('complete')}")

    if not sign_result.get("complete"):
        print("ERROR: Transaction signing failed!")
        print(f"  Result: {json.dumps(sign_result, indent=2)}")
        sys.exit(1)

    signed_hex = sign_result["hex"]
    print(f"  Signed tx size: {len(signed_hex) // 2} bytes")

    # Ask for confirmation before broadcasting
    print(f"\n{'='*60}")
    print(f"READY TO BROADCAST bridge deposit transaction:")
    print(f"  Amount: {DEPOSIT_AMOUNT_DIL} DIL")
    print(f"  To: {BRIDGE_ADDRESS}")
    print(f"  Base address: {BASE_ADDRESS}")
    print(f"  Fee: {FEE_DIL} DIL")
    print(f"{'='*60}")

    confirm = input("\nType 'yes' to broadcast: ")
    if confirm.strip().lower() != "yes":
        print("Aborted.")
        sys.exit(0)

    # Broadcast
    print("\nBroadcasting transaction...")
    result = rpc._call("sendrawtransaction", {"hex": signed_hex})
    print(f"\nTransaction broadcast! Result: {result}")


if __name__ == "__main__":
    main()
