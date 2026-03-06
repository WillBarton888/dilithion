================================================================
  DilV - POST-QUANTUM PAYMENTS CHAIN
  MAINNET RELEASE - LINUX
================================================================

Welcome to DilV!

This is the MAINNET. DilV coins you mine here are real.

================================================================
  WHAT IS DilV?
================================================================

DilV is the fast-payments companion chain to Dilithion (DIL).
It uses VDF (Verifiable Delay Function) consensus — a provably
fair distribution where any CPU participates equally. No GPU,
no ASIC, no mining pools needed.

With DilV you can:
  - Mine DilV using any CPU (fair VDF distribution)
  - Send fast quantum-resistant payments (~45s blocks)
  - Use DilV for x402 micropayments and AI agent payments
  - Atomically swap DilV for DIL (trustless, no exchange)

Exchange rate: ~10 DilV = 1 DIL (natural emission ratio)

================================================================
  INSTALL DEPENDENCIES (REQUIRED FIRST!)
================================================================

Before running DilV, install the required libraries:

UBUNTU / DEBIAN:
  sudo apt-get update
  sudo apt-get install libleveldb-dev libsnappy-dev libgmp-dev

FEDORA / RHEL / CENTOS:
  sudo dnf install leveldb-devel snappy-devel gmp-devel

ARCH LINUX:
  sudo pacman -S leveldb snappy gmp

ALPINE LINUX:
  sudo apk add leveldb-dev snappy-dev gmp-dev

These libraries are required for the blockchain database and
VDF computation.

================================================================
  GETTING STARTED
================================================================

OPTION 1: ONE-CLICK MINING (Recommended)
---------------------------------------
1. Open terminal in this directory
2. Run: ./start-dilv-mining.sh
3. You're mining DilV!

OPTION 2: INTERACTIVE SETUP
---------------------------------------
1. Run: ./setup-dilv.sh
2. Follow the on-screen instructions

OPTION 3: DIRECT COMMAND
---------------------------------------
  ./dilv-node --mine

For relay-only (no mining):
  ./dilv-node --relay-only

All options:
  ./dilv-node --help

================================================================
  WHAT TO EXPECT WHEN MINING
================================================================

1. CONNECTION
   - "Connected to peer: 138.197.68.128:9444"
   - Connects to one of the official seed nodes

2. BLOCKCHAIN SYNC
   - "Downloading blocks..." — first sync takes a few minutes
   - Much lighter than DIL (no RandomX cache needed)
   - Requires ~512 MB RAM

3. VDF MINING
   - "Computing VDF proof for block XXXXX..."
   - "VDF block found! Submitted to network."
   - Each attempt takes ~4-11 seconds of sequential computation

4. BLOCK WINS
   - Your proof competes against other miners by output value
   - Lower output = better (lottery-style)
   - Expected win rate is proportional to your speed

================================================================
  FREQUENTLY ASKED QUESTIONS
================================================================

Q: How is VDF mining different from RandomX?
A: VDF is sequential (cannot be parallelised). Your CPU computes
   one VDF proof per block window. The miner with the lowest
   output wins. Speed matters, but you can't buy more lottery
   tickets with more hardware.

Q: How long until I win a block?
A: Block time is ~45 seconds. With N miners on the network,
   you win roughly 1 in N blocks on average.

Q: How much RAM does DilV mining need?
A: ~512 MB. Much less than DIL (which needs 2.5 GB for RandomX).

Q: How do I check my balance?
A: Run: ./check-wallet-balance

Q: What is the block reward?
A: 100 DilV per block. A 2% mining tax applies (1% dev fund,
   1% developer reward) — same as DIL mainnet.

Q: What are the official seed nodes?
A: NYC:       138.197.68.128:9444   (Primary)
   London:    167.172.56.119:9444   (Europe)
   Singapore: 165.22.103.114:9444   (Asia-Pacific)
   Sydney:    134.199.159.83:9444   (Oceania)

Q: How do I swap DilV for DIL?
A: Use the built-in atomic swap RPC commands (trustless, no
   exchange needed). See: dilv-node --help

================================================================
  SYSTEM REQUIREMENTS
================================================================

- Linux kernel 3.2+ (Ubuntu 18.04+, Debian 10+, etc.)
- 512 MB RAM minimum (no RandomX cache needed)
- 1 GB disk space
- x86_64 (64-bit) processor
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilv-node              Main node software (mining + wallet)
check-wallet-balance   Check your DilV balance

start-dilv-mining.sh   One-click mining launcher
setup-dilv.sh          Interactive first-time setup
run-node.sh            Wrapper with bundled library paths

README.txt             This file

================================================================
  NEED HELP?
================================================================

Website:     https://dilithion.org
Telegram:    https://t.me/dilithion
Source Code: https://github.com/dilithion/dilithion
Report bugs: https://github.com/dilithion/dilithion/issues

================================================================
  QUANTUM-RESISTANT CRYPTOGRAPHY
================================================================

DilV uses CRYSTALS-Dilithium (NIST FIPS 204) for all signatures.
Every transaction is quantum-resistant from genesis.

This protects against "Harvest Now, Decrypt Later" attacks —
your DilV transactions are safe even from future quantum
computers.

================================================================

Happy mining!

The Dilithion Team
https://dilithion.org

================================================================
