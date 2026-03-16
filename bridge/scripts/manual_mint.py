#!/usr/bin/env python3
"""
Manual mint script — use when a deposit was sent to a retired bridge address
or any case where the relayer couldn't process the deposit automatically.

Usage:
    python manual_mint.py \
        --chain dil \
        --txid <native_txid> \
        --amount <coins>  \
        --to <0x_base_address>

Example (caspar2114 case):
    python manual_mint.py \
        --chain dil \
        --txid 25d687140c238134024ca129eff1dcf3744a686908f4ea76385572c0911146f5 \
        --amount 360 \
        --to 0x9ea6f69fd171eaaba2089e2b37c7657b18708dba
"""

import argparse
import sys
import os
from pathlib import Path

# Load relayer config from bridge/.env
sys.path.insert(0, str(Path(__file__).parent.parent / "relayer"))
import config

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

WTOKEN_ABI = [
    {
        "inputs": [
            {"name": "to",          "type": "address"},
            {"name": "amount",      "type": "uint256"},
            {"name": "nativeTxId",  "type": "bytes32"},
        ],
        "name": "mint",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "", "type": "bytes32"}],
        "name": "minted",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

CONTRACTS = {
    "dil":  config.WDIL_CONTRACT,
    "dilv": config.WDILV_CONTRACT,
}
COINS = {
    "dil":  "wDIL",
    "dilv": "wDILV",
}


def main():
    parser = argparse.ArgumentParser(description="Manually mint wTokens for a missed deposit")
    parser.add_argument("--chain",  required=True, choices=["dil", "dilv"])
    parser.add_argument("--txid",   required=True, help="Native chain txid of the deposit")
    parser.add_argument("--amount", required=True, type=float, help="Amount in coins (e.g. 360)")
    parser.add_argument("--to",     required=True, help="Destination Base address (0x...)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without sending")
    args = parser.parse_args()

    chain    = args.chain
    coin     = COINS[chain]
    amount_sats = int(round(args.amount * 1e8))
    to_addr  = Web3.to_checksum_address(args.to)
    txid_hex = args.txid.strip()

    if len(txid_hex) != 64:
        print(f"ERROR: txid must be 64 hex chars, got {len(txid_hex)}")
        sys.exit(1)

    txid_bytes = bytes.fromhex(txid_hex)

    contract_addr = CONTRACTS[chain]
    if not contract_addr:
        print(f"ERROR: No contract address configured for {chain}")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(config.BASE_RPC_URL))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        print(f"ERROR: Cannot connect to Base RPC: {config.BASE_RPC_URL}")
        sys.exit(1)

    if not config.BRIDGE_PRIVATE_KEY:
        print("ERROR: DEPLOYER_PRIVATE_KEY not set in .env")
        sys.exit(1)

    account = w3.eth.account.from_key(config.BRIDGE_PRIVATE_KEY)
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_addr),
        abi=WTOKEN_ABI,
    )

    # Check replay protection — has this txid already been minted?
    already_minted = contract.functions.minted(txid_bytes).call()

    print(f"\n{'='*60}")
    print(f"Manual mint summary:")
    print(f"  Chain:        {chain.upper()}")
    print(f"  Token:        {coin}")
    print(f"  Contract:     {contract_addr}")
    print(f"  Recipient:    {to_addr}")
    print(f"  Amount:       {args.amount} {coin} ({amount_sats} sats)")
    print(f"  Native txid:  {txid_hex}")
    print(f"  Minter:       {account.address}")
    print(f"  Already minted on-chain: {already_minted}")
    print(f"{'='*60}\n")

    if already_minted:
        print("Contract says this txid was already minted. Nothing to do.")
        sys.exit(0)

    if args.dry_run:
        print("DRY RUN — would call mint() with the above parameters. Exiting.")
        sys.exit(0)

    confirm = input("Type 'yes' to broadcast the mint transaction: ")
    if confirm.strip().lower() != "yes":
        print("Aborted.")
        sys.exit(0)

    tx = contract.functions.mint(
        to_addr,
        amount_sats,
        txid_bytes,
    ).build_transaction({
        "from":               account.address,
        "nonce":              w3.eth.get_transaction_count(account.address, "pending"),
        "gas":                150_000,
        "maxFeePerGas":       w3.eth.gas_price * 2,
        "maxPriorityFeePerGas": w3.to_wei(0.001, "gwei"),
    })

    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"Sent! Waiting for receipt... (tx: {tx_hash.hex()})")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status == 1:
        print(f"\nSUCCESS: Minted {args.amount} {coin} to {to_addr}")
        print(f"Base tx: {tx_hash.hex()}")
    else:
        print(f"\nFAILED: Mint tx reverted. Hash: {tx_hash.hex()}")
        sys.exit(1)


if __name__ == "__main__":
    main()
