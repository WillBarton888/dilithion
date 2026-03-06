================================================================
  DilV - POST-QUANTUM PAYMENTS CHAIN
  MAINNET RELEASE - macOS
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

Install Homebrew dependencies:

  brew install leveldb gmp openssl miniupnpc

These are required for the blockchain database and VDF
computation. If you don't have Homebrew:
  https://brew.sh

================================================================
  GETTING STARTED
================================================================

OPTION 1: ONE-CLICK MINING (Recommended)
---------------------------------------
1. Open Terminal in this directory
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
  FIRST TIME: MAKE SCRIPTS EXECUTABLE
================================================================

If macOS shows a permission error, run:

  chmod +x dilv-node
  chmod +x check-wallet-balance
  chmod +x start-dilv-mining.sh
  chmod +x setup-dilv.sh

Also, macOS may show a security warning the first time.
Go to: System Preferences → Security & Privacy → Allow

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

================================================================
  FREQUENTLY ASKED QUESTIONS
================================================================

Q: How is VDF mining different from RandomX?
A: VDF is sequential (cannot be parallelised). Your CPU computes
   one VDF proof per block window. The miner with the lowest
   output wins the block. Speed matters, but you can't buy more
   lottery tickets with more hardware — it stays fair.

Q: How much RAM does DilV mining need?
A: ~512 MB. Much less than DIL (which needs 2.5 GB for RandomX).

Q: How do I check my balance?
A: Run: ./check-wallet-balance

Q: What is the block reward?
A: 100 DilV per block (2% mining tax: 1% dev fund + 1% dev
   reward, same as DIL mainnet).

Q: What are the official seed nodes?
A: NYC:       138.197.68.128:9444   (Primary)
   London:    167.172.56.119:9444   (Europe)
   Singapore: 165.22.103.114:9444   (Asia-Pacific)
   Sydney:    134.199.159.83:9444   (Oceania)

================================================================
  SYSTEM REQUIREMENTS
================================================================

- macOS 10.15 (Catalina) or later
- 512 MB RAM minimum
- 1 GB disk space
- x86_64 or Apple Silicon (via Rosetta 2)
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilv-node              Main node software (mining + wallet)
check-wallet-balance   Check your DilV balance

start-dilv-mining.sh   One-click mining launcher
setup-dilv.sh          Interactive first-time setup

README.txt             This file

================================================================
  NEED HELP?
================================================================

Website:     https://dilithion.org
Telegram:    https://t.me/dilithion
Source Code: https://github.com/dilithion/dilithion
Report bugs: https://github.com/dilithion/dilithion/issues

================================================================

Happy mining!

The Dilithion Team
https://dilithion.org

================================================================
