#!/usr/bin/env python3
"""
Dilithion Arbitrage Bot
========================
Maintains the 10:1 DIL/DilV ratio across Aerodrome DEX pools on Base.

Architecture:
  - Reads prices from Slipstream (wDIL/WETH) and stable pool (wDIL/wDilV)
  - When the ratio diverges beyond threshold, executes corrective trades
  - All trades happen on-chain on Base — no bridging per trade

Usage:
    python arb_bot.py [--dry-run]
"""

import argparse
import json
import logging
import os
import random
import sys
import time
from decimal import Decimal

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

import config

logger = logging.getLogger("arb_bot")

# ── Aerodrome contract addresses (Base mainnet) ─────────────────────

# Slipstream (concentrated liquidity)
SLIPSTREAM_QUOTER = "0x3d4C22254F86f64B7eC90ab8F7aeC1FBFD271c6C"
SLIPSTREAM_ROUTER = "0xcbBb8035cAc7D4B3Ca7aBb74cF7BdF900215Ce0D"

# Classic AMM
CLASSIC_ROUTER = "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43"
POOL_FACTORY   = "0x420DD381b31aEf6683db6B902084cB0FFECe40Da"

# Tokens
WETH9 = "0x4200000000000000000000000000000000000006"

# ── Config from environment ──────────────────────────────────────────

ARB_ENABLED        = os.getenv("ARB_ENABLED", "true").lower() == "true"
ARB_RATIO_TARGET   = float(os.getenv("ARB_RATIO_TARGET", "10.0"))
ARB_RATIO_TOLERANCE = float(os.getenv("ARB_RATIO_TOLERANCE", "0.05"))  # 5%
ARB_MAX_TRADE_DIL  = int(os.getenv("ARB_MAX_TRADE_SIZE_DIL", "100"))   # max DIL per trade
ARB_INTERVAL       = int(os.getenv("ARB_INTERVAL_SECONDS", "30"))
ARB_INTERVAL_JITTER = int(os.getenv("ARB_INTERVAL_JITTER", "15"))      # ±15s random jitter
ARB_SLIPPAGE_BPS   = int(os.getenv("ARB_SLIPPAGE_BPS", "100"))         # 1% max slippage (100 bps)
TICK_SPACING       = 200  # CL200 for volatile pairs

# ── ABI fragments ────────────────────────────────────────────────────

ERC20_ABI = json.loads("""[
    {"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],
     "name":"approve","outputs":[{"type":"bool"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],
     "name":"allowance","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"name":"account","type":"address"}],
     "name":"balanceOf","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"decimals","outputs":[{"type":"uint8"}],"stateMutability":"view","type":"function"}
]""")

QUOTER_ABI = json.loads("""[
    {"inputs":[
        {"components":[
            {"name":"tokenIn","type":"address"},
            {"name":"tokenOut","type":"address"},
            {"name":"amountIn","type":"uint256"},
            {"name":"tickSpacing","type":"int24"},
            {"name":"sqrtPriceLimitX96","type":"uint160"}
        ],"name":"params","type":"tuple"}
    ],
    "name":"quoteExactInputSingle",
    "outputs":[
        {"name":"amountOut","type":"uint256"},
        {"name":"sqrtPriceX96After","type":"uint160"},
        {"name":"initializedTicksCrossed","type":"uint32"},
        {"name":"gasEstimate","type":"uint256"}
    ],
    "stateMutability":"nonpayable","type":"function"}
]""")

SLIPSTREAM_ROUTER_ABI = json.loads("""[
    {"inputs":[
        {"components":[
            {"name":"tokenIn","type":"address"},
            {"name":"tokenOut","type":"address"},
            {"name":"tickSpacing","type":"int24"},
            {"name":"recipient","type":"address"},
            {"name":"deadline","type":"uint256"},
            {"name":"amountIn","type":"uint256"},
            {"name":"amountOutMinimum","type":"uint256"},
            {"name":"sqrtPriceLimitX96","type":"uint160"}
        ],"name":"params","type":"tuple"}
    ],
    "name":"exactInputSingle",
    "outputs":[{"name":"amountOut","type":"uint256"}],
    "stateMutability":"payable","type":"function"}
]""")

CLASSIC_ROUTER_ABI = json.loads("""[
    {"inputs":[
        {"name":"amountIn","type":"uint256"},
        {"name":"amountOutMin","type":"uint256"},
        {"components":[
            {"name":"from","type":"address"},
            {"name":"to","type":"address"},
            {"name":"stable","type":"bool"},
            {"name":"factory","type":"address"}
        ],"name":"routes","type":"tuple[]"},
        {"name":"to","type":"address"},
        {"name":"deadline","type":"uint256"}
    ],
    "name":"swapExactTokensForTokens",
    "outputs":[{"name":"amounts","type":"uint256[]"}],
    "stateMutability":"nonpayable","type":"function"},
    {"inputs":[
        {"name":"amountIn","type":"uint256"},
        {"components":[
            {"name":"from","type":"address"},
            {"name":"to","type":"address"},
            {"name":"stable","type":"bool"},
            {"name":"factory","type":"address"}
        ],"name":"routes","type":"tuple[]"}
    ],
    "name":"getAmountsOut",
    "outputs":[{"name":"amounts","type":"uint256[]"}],
    "stateMutability":"view","type":"function"}
]""")


class ArbBot:
    """Monitors prices and executes arbitrage trades to maintain 10:1 ratio."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

        # Base connection (FCFS sequencer — no public mempool on Base)
        self.w3 = Web3(Web3.HTTPProvider(
            config.BASE_RPC_URL if config.NETWORK == "mainnet"
            else "https://sepolia.base.org"
        ))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if config.BRIDGE_PRIVATE_KEY:
            self.account = self.w3.eth.account.from_key(config.BRIDGE_PRIVATE_KEY)
        else:
            self.account = None
            logger.warning("No private key — trades disabled")

        # Token contracts
        self.wdil_addr = Web3.to_checksum_address(config.WDIL_CONTRACT)
        self.wdilv_addr = Web3.to_checksum_address(config.WDILV_CONTRACT)
        self.weth_addr = Web3.to_checksum_address(WETH9)

        self.wdil = self.w3.eth.contract(address=self.wdil_addr, abi=ERC20_ABI)
        self.wdilv = self.w3.eth.contract(address=self.wdilv_addr, abi=ERC20_ABI)

        # DEX contracts
        self.quoter = self.w3.eth.contract(
            address=Web3.to_checksum_address(SLIPSTREAM_QUOTER), abi=QUOTER_ABI
        )
        self.sl_router = self.w3.eth.contract(
            address=Web3.to_checksum_address(SLIPSTREAM_ROUTER), abi=SLIPSTREAM_ROUTER_ABI
        )
        self.cl_router = self.w3.eth.contract(
            address=Web3.to_checksum_address(CLASSIC_ROUTER), abi=CLASSIC_ROUTER_ABI
        )

        # Stats
        self.total_trades = 0
        self.total_dil_traded = 0

    def run(self):
        """Main loop — poll prices and arb when ratio diverges."""
        logger.info("Arb bot starting...")
        logger.info(f"  Network:      {config.NETWORK.upper()}")
        logger.info(f"  wDIL:         {self.wdil_addr}")
        logger.info(f"  wDILV:        {self.wdilv_addr}")
        logger.info(f"  Target ratio: {ARB_RATIO_TARGET}")
        logger.info(f"  Tolerance:    ±{ARB_RATIO_TOLERANCE * 100:.0f}%")
        logger.info(f"  Max trade:    {ARB_MAX_TRADE_DIL} DIL")
        logger.info(f"  Slippage:     {ARB_SLIPPAGE_BPS} bps ({ARB_SLIPPAGE_BPS/100:.1f}%)")
        logger.info(f"  Interval:     {ARB_INTERVAL}s ±{ARB_INTERVAL_JITTER}s jitter")
        logger.info(f"  Dry run:      {self.dry_run}")

        while True:
            try:
                self._check_and_arb()
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Arb loop error: {e}", exc_info=True)

            # Randomize interval to make trade timing unpredictable
            jitter = random.randint(-ARB_INTERVAL_JITTER, ARB_INTERVAL_JITTER)
            sleep_time = max(10, ARB_INTERVAL + jitter)
            time.sleep(sleep_time)

    def _check_and_arb(self):
        """Check prices and execute arb if needed."""
        # Get prices
        dil_eth_price = self._get_dil_eth_price()
        stable_ratio = self._get_stable_ratio()

        if stable_ratio is None:
            logger.debug("Could not get stable pool ratio (pool may not exist yet)")
            return

        # Log current state (ETH price is optional — Slipstream pool may lack liquidity)
        eth_str = f"{dil_eth_price:.8f}" if dil_eth_price else "N/A"
        logger.info(
            f"Prices: 1 DIL = {eth_str} ETH | "
            f"Stable ratio: {stable_ratio:.2f} DilV/DIL | "
            f"Target: {ARB_RATIO_TARGET}"
        )

        # Check if ratio is out of bounds
        upper_bound = ARB_RATIO_TARGET * (1 + ARB_RATIO_TOLERANCE)
        lower_bound = ARB_RATIO_TARGET * (1 - ARB_RATIO_TOLERANCE)

        if stable_ratio > upper_bound:
            # DilV is too cheap vs DIL — buy DilV, sell DIL
            logger.info(
                f"RATIO HIGH: {stable_ratio:.2f} > {upper_bound:.2f} — "
                f"DilV underpriced, buying DilV with DIL"
            )
            self._arb_buy_dilv()
        elif stable_ratio < lower_bound:
            # DIL is too cheap vs DilV — buy DIL, sell DilV
            logger.info(
                f"RATIO LOW: {stable_ratio:.2f} < {lower_bound:.2f} — "
                f"DIL underpriced, buying DIL with DilV"
            )
            self._arb_buy_dil()

    def _get_dil_eth_price(self) -> float | None:
        """Get wDIL price in ETH from Slipstream pool via Quoter."""
        try:
            # Quote: how much WETH for 1 wDIL?
            one_dil = 100_000_000  # 1 DIL in ions (8 decimals)
            result = self.quoter.functions.quoteExactInputSingle((
                self.wdil_addr,   # tokenIn
                self.weth_addr,   # tokenOut
                one_dil,          # amountIn
                TICK_SPACING,     # tickSpacing
                0,                # sqrtPriceLimitX96 (0 = no limit)
            )).call()
            weth_out = result[0]
            return float(weth_out) / 1e18  # Convert wei to ETH
        except Exception as e:
            logger.debug(f"Quoter error: {e}")
            return None

    def _get_stable_ratio(self) -> float | None:
        """Get wDIL/wDilV ratio from volatile pool.

        Returns how many DilV you get per 1 DIL (target: 10.0).
        """
        try:
            one_dil = 100_000_000  # 1 DIL in ions
            routes = [(
                self.wdil_addr,  # from
                self.wdilv_addr, # to
                False,           # volatile (x*y=k) pool
                Web3.to_checksum_address(POOL_FACTORY),
            )]
            amounts = self.cl_router.functions.getAmountsOut(one_dil, routes).call()
            dilv_out = amounts[-1]
            return float(dilv_out) / 1e8  # Convert volts to DilV
        except Exception as e:
            logger.debug(f"Stable pool quote error: {e}")
            return None

    def _arb_buy_dilv(self):
        """Buy wDilV with wDIL on the stable pool (ratio too high)."""
        trade_amount = ARB_MAX_TRADE_DIL * 100_000_000  # Convert to ions

        # Check wDIL balance
        balance = self.wdil.functions.balanceOf(self.account.address).call()
        if balance < trade_amount:
            logger.warning(
                f"Insufficient wDIL for arb: {balance / 1e8:.2f} < {ARB_MAX_TRADE_DIL}"
            )
            return

        if self.dry_run:
            logger.info(
                f"DRY RUN: Would swap {ARB_MAX_TRADE_DIL} wDIL → wDilV on stable pool"
            )
            return

        self._swap_on_stable_pool(self.wdil_addr, self.wdilv_addr, trade_amount)

    def _arb_buy_dil(self):
        """Buy wDIL with wDilV on the stable pool (ratio too low)."""
        # Trade 10x DilV equivalent
        trade_amount = ARB_MAX_TRADE_DIL * 10 * 100_000_000  # DilV in volts

        # Check wDilV balance
        balance = self.wdilv.functions.balanceOf(self.account.address).call()
        if balance < trade_amount:
            logger.warning(
                f"Insufficient wDilV for arb: {balance / 1e8:.2f} < "
                f"{ARB_MAX_TRADE_DIL * 10}"
            )
            return

        if self.dry_run:
            logger.info(
                f"DRY RUN: Would swap {ARB_MAX_TRADE_DIL * 10} wDilV → wDIL on stable pool"
            )
            return

        self._swap_on_stable_pool(self.wdilv_addr, self.wdil_addr, trade_amount)

    def _get_expected_output(self, token_in: str, token_out: str, amount_in: int) -> int:
        """Quote expected output from the volatile pool (read-only, no tx)."""
        routes = [(
            token_in,
            token_out,
            False,  # volatile (x*y=k) pool
            Web3.to_checksum_address(POOL_FACTORY),
        )]
        amounts = self.cl_router.functions.getAmountsOut(amount_in, routes).call()
        return amounts[-1]

    def _swap_on_stable_pool(self, token_in: str, token_out: str, amount_in: int):
        """Execute a swap on the Aerodrome classic volatile pool.

        Uses MEV-protected RPC to send trades to a private mempool,
        preventing sandwich attacks. Includes slippage protection based
        on a pre-swap quote.
        """
        try:
            # Get expected output and enforce slippage limit
            expected_out = self._get_expected_output(token_in, token_out, amount_in)
            min_out = expected_out * (10_000 - ARB_SLIPPAGE_BPS) // 10_000
            logger.info(
                f"Quote: {amount_in / 1e8:.2f} in → "
                f"{expected_out / 1e8:.2f} expected, "
                f"{min_out / 1e8:.2f} minimum ({ARB_SLIPPAGE_BPS}bps slippage)"
            )

            if expected_out == 0:
                logger.warning("Quote returned 0 — skipping trade")
                return

            # Safe gas params for Base L2 (very low base fee ~0.006 gwei)
            nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")
            gas_price = self.w3.eth.gas_price
            max_fee = max(gas_price * 2, self.w3.to_wei(0.01, "gwei"))
            priority_fee = min(self.w3.to_wei(0.001, "gwei"), max_fee)
            gas_params = {"maxFeePerGas": max_fee, "maxPriorityFeePerGas": priority_fee}
            router_addr = Web3.to_checksum_address(CLASSIC_ROUTER)

            # Only approve if allowance is insufficient (max uint256 so we approve once)
            token_contract = self.w3.eth.contract(address=token_in, abi=ERC20_ABI)
            allowance = token_contract.functions.allowance(
                self.account.address, router_addr
            ).call()

            if allowance < amount_in:
                max_approval = 2**256 - 1
                approve_tx = token_contract.functions.approve(
                    router_addr, max_approval
                ).build_transaction({
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": 100_000,
                    **gas_params,
                })
                signed = self.account.sign_transaction(approve_tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                logger.info(f"Approved {token_in[:10]}... to router")
                nonce += 1  # Explicit increment — don't re-query

            # Swap with slippage protection
            routes = [(
                token_in,
                token_out,
                False,  # volatile (x*y=k) pool
                Web3.to_checksum_address(POOL_FACTORY),
            )]
            deadline = int(time.time()) + 120  # 2 min

            swap_tx = self.cl_router.functions.swapExactTokensForTokens(
                amount_in,
                min_out,  # slippage-protected minimum output
                routes,
                self.account.address,
                deadline,
            ).build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "gas": 300_000,
                **gas_params,
            })
            signed = self.account.sign_transaction(swap_tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt.status == 1:
                self.total_trades += 1
                self.total_dil_traded += amount_in / 1e8
                logger.info(
                    f"SWAP OK: {amount_in / 1e8:.2f} {token_in[:8]}... → "
                    f"{token_out[:8]}... (tx: {tx_hash.hex()[:16]}...)"
                )
            else:
                logger.error(f"Swap reverted: {tx_hash.hex()}")

        except Exception as e:
            logger.error(f"Swap failed: {e}")


# ── Entry point ──────────────────────────────────────────────────────

def setup_logging():
    """Configure logging."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    handler.flush = sys.stdout.flush

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        handlers=[handler],
    )


def main():
    parser = argparse.ArgumentParser(description="Dilithion Arb Bot")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Monitor prices but don't execute trades"
    )
    args = parser.parse_args()

    setup_logging()

    if not ARB_ENABLED:
        logger.info("Arb bot disabled (ARB_ENABLED=false). Exiting.")
        return

    if not config.WDIL_CONTRACT or not config.WDILV_CONTRACT:
        logger.error("WDIL_CONTRACT and WDILV_CONTRACT must be set. Exiting.")
        return

    bot = ArbBot(dry_run=args.dry_run)
    bot.run()


if __name__ == "__main__":
    main()
