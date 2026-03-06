================================================================
  DilV - POST-QUANTUM PAYMENTS CHAIN
  MAINNET RELEASE - WINDOWS
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
  GETTING STARTED
================================================================

OPTION 1: INTERACTIVE SETUP (Recommended)
---------------------------------------
Double-click: SETUP-DILV.bat

This will ask if you want to mine or run as a relay node.

OPTION 2: ONE-CLICK MINING
---------------------------------------
Double-click: START-DILV-MINING.bat

OPTION 3: COMMAND PROMPT
---------------------------------------
  dilv-node.exe --mine
  dilv-node.exe --relay-only
  dilv-node.exe --help

================================================================
  WHERE IS MY WALLET?
================================================================

Your DilV wallet is stored at:
  %APPDATA%\.dilv\

(e.g. C:\Users\YourName\AppData\Roaming\.dilv\)

IMPORTANT: Back up your wallet regularly!
  Copy the entire .dilv folder to a safe location.

To check your balance:
  Double-click check-wallet-balance.exe
  Or run: check-wallet-balance.exe in Command Prompt

================================================================
  WHAT TO EXPECT WHEN MINING
================================================================

1. CONNECTION
   A window appears and connects to seed nodes:
     "Connected to peer: 138.197.68.128:9444"

2. BLOCKCHAIN SYNC
   "Downloading blocks..." — syncs in a few minutes.
   Only needs ~512 MB RAM (much less than DIL).

3. VDF MINING
   "Computing VDF proof for block XXXXX..."
   "VDF block found! Submitted to network."
   Each attempt takes ~4-11 seconds on typical hardware.

================================================================
  FREQUENTLY ASKED QUESTIONS
================================================================

Q: How is VDF mining different from RandomX (DIL)?
A: VDF is sequential (cannot be parallelised or GPU-accelerated).
   Everyone competes fairly on a per-attempt basis. The miner
   with the lowest VDF output wins the block.

Q: How much RAM does DilV mining need?
A: ~512 MB. Much less than DIL (which needs 2.5 GB for RandomX).

Q: What is the block reward?
A: 100 DilV per block. A 2% tax applies (1% dev fund, 1% dev
   reward) — same structure as DIL mainnet.

Q: What are the official seed nodes?
A: NYC:       138.197.68.128:9444   (Primary)
   London:    167.172.56.119:9444   (Europe)
   Singapore: 165.22.103.114:9444   (Asia-Pacific)
   Sydney:    134.199.159.83:9444   (Oceania)

Q: Windows Defender is flagging it — is it safe?
A: This is a false positive common with cryptocurrency miners.
   The software is open source: github.com/dilithion/dilithion
   You can add an exclusion for the DilV folder in Windows
   Security settings.

Q: How do I swap DilV for DIL?
A: Use the built-in atomic swap RPC from the command prompt.
   See the website for a step-by-step guide.

================================================================
  SYSTEM REQUIREMENTS
================================================================

- Windows 10 or 11 (64-bit)
- 512 MB RAM minimum
- 1 GB disk space
- x86-64 processor
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilv-node.exe           Main node software (mining + wallet)
check-wallet-balance.exe  Check your DilV balance

SETUP-DILV.bat          Interactive setup menu
START-DILV-MINING.bat   One-click mining start

*.dll                   Required runtime libraries (keep these
                        in the same folder as dilv-node.exe)

wallet.html             Web wallet interface (open in browser)
README.txt              This file

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
