"""Bridge relayer configuration — loaded from environment variables."""

import os
from dotenv import load_dotenv

# Load .env from bridge/ directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# ── Network selection ────────────────────────────────────────────────
# "mainnet" or "testnet" — controls defaults and validation
NETWORK = os.getenv("NETWORK", "testnet")

# ── Dilithion chain RPC ──────────────────────────────────────────────
DIL_RPC_URL  = os.getenv("DIL_RPC_URL",  "http://127.0.0.1:8332")
DILV_RPC_URL = os.getenv("DILV_RPC_URL", "http://127.0.0.1:9332")
RPC_USER     = os.getenv("RPC_USER",     "rpc")
RPC_PASSWORD = os.getenv("RPC_PASSWORD", "rpc")

# ── Base chain ───────────────────────────────────────────────────────
_default_base_rpc = "https://mainnet.base.org" if NETWORK == "mainnet" else "https://sepolia.base.org"
BASE_RPC_URL       = os.getenv("BASE_RPC_URL", _default_base_rpc)
BRIDGE_PRIVATE_KEY = os.getenv("DEPLOYER_PRIVATE_KEY", "")

# ── Deployed contract addresses ──────────────────────────────────────
WDIL_CONTRACT  = os.getenv("WDIL_CONTRACT",  "")
WDILV_CONTRACT = os.getenv("WDILV_CONTRACT", "")

# ── Bridge deposit addresses (native chains) ─────────────────────────
DIL_BRIDGE_ADDRESS  = os.getenv("DIL_BRIDGE_ADDRESS",  "")
DILV_BRIDGE_ADDRESS = os.getenv("DILV_BRIDGE_ADDRESS", "")

# ── Confirmation thresholds ──────────────────────────────────────────
DIL_CONFIRMATIONS  = int(os.getenv("DIL_CONFIRMATIONS",  "6"))    # ~24 min
DILV_CONFIRMATIONS = int(os.getenv("DILV_CONFIRMATIONS", "15"))   # ~12 min
BASE_CONFIRMATIONS = int(os.getenv("BASE_CONFIRMATIONS", "12"))   # ~24 sec

# ── Safety limits (relayer-side, independent of contract limits) ─────
# Values in smallest units (ions for DIL, volts for DilV)
DAILY_MINT_CAP_DIL  = int(os.getenv("DAILY_MINT_CAP_DIL",  str(10_000_00000000)))
DAILY_MINT_CAP_DILV = int(os.getenv("DAILY_MINT_CAP_DILV", str(100_000_00000000)))
MAX_PER_DEPOSIT_DIL  = int(os.getenv("MAX_PER_DEPOSIT_DIL",  str(1_000_00000000)))
MAX_PER_DEPOSIT_DILV = int(os.getenv("MAX_PER_DEPOSIT_DILV", str(10_000_00000000)))

# ── Bridge OP_RETURN tag ─────────────────────────────────────────────
BRIDGE_TAG = b"DBRG"

# ── Polling ──────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "10"))

# ── Gas alert threshold (ETH on Base) ────────────────────────────────
GAS_ALERT_THRESHOLD_ETH = float(os.getenv("GAS_ALERT_THRESHOLD_ETH", "0.01"))

# ── Logging ──────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE  = os.getenv("LOG_FILE",  "")  # empty = stdout only
