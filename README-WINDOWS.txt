================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  MAINNET RELEASE - WINDOWS
================================================================

Welcome to Dilithion!

This is the MAINNET. DIL coins you mine here are real.

================================================================
  WHAT IS DILITHION?
================================================================

Dilithion is a post-quantum cryptocurrency that uses NIST-
standardized cryptography (CRYSTALS-Dilithium, SHA-3) to protect
against future quantum computer attacks.

With Dilithion you can:
  - Mine DIL coins using your CPU
  - Send and receive quantum-resistant transactions
  - Run a full node to support the network

================================================================
  GETTING STARTED - THREE EASY WAYS
================================================================

OPTION 1: INTERACTIVE SETUP WIZARD (Recommended for first time!)
---------------------------------------
1. Double-click: SETUP-AND-START.bat
2. Follow the on-screen instructions
3. Choose how many CPU cores to use
4. Start mining!

The wizard will walk you through each step.


OPTION 2: ONE-CLICK MINING (Quick start)
---------------------------------------
1. Double-click: START-MINING.bat
2. Wait a few seconds
3. You're mining!

The script automatically:
  - Connects to the official seed nodes
  - Detects your CPU cores
  - Starts mining DIL


OPTION 3: ADVANCED (Command Line)
---------------------------------------
1. Open Command Prompt (cmd.exe)
2. Navigate to this folder:
   cd C:\path\to\dilithion
3. Run with no arguments for auto-start:
   dilithion-node.exe

   Or customize with arguments:
   dilithion-node.exe --mine --threads=4

   For all options:
   dilithion-node.exe --help

================================================================
  HOW TO STOP MINING
================================================================

Press Ctrl+C in the window where the miner is running.

The node will shut down gracefully.

================================================================
  WHAT TO EXPECT WHEN MINING
================================================================

When you start mining, you'll see:

1. CONNECTION MESSAGES
   - "Connected to peer: 138.197.68.128:8444" (or London/Singapore/Sydney)
   - This means you've connected to one of the official seed nodes

2. BLOCKCHAIN SYNC
   - "Downloading blocks..."
   - Your node catches up to the latest block
   - First sync requires ~2.5 GB RAM for RandomX initialization

3. MINING MESSAGES
   - "Mining block at height XXXXX..."
   - "Block found! Hash: 00000..."
   - Your CPU is trying to find new blocks

4. NETWORK ACTIVITY
   - Messages about peers connecting/disconnecting
   - New blocks discovered by other miners

================================================================
  FREQUENTLY ASKED QUESTIONS
================================================================

Q: How long until I mine a block?
A: Block time is ~4 minutes. With multiple miners on the network,
   it depends on your CPU power relative to the total hashrate.
   Be patient - mining is competitive!

Q: How do I check my balance?
A: Run: check-wallet-balance.exe
   This shows your DIL balance.

Q: Is mining safe for my computer?
A: Mining is safe. It uses CPU only (no GPU needed) and won't
   harm your computer. The miner runs in a normal window you
   can close anytime.
   Note: RandomX mining uses ~2.5 GB RAM.

Q: Can I mine on a laptop?
A: Yes, but laptops may get warm. Use the wizard to choose
   1-2 cores for light mining. Desktop PCs handle mining better.

Q: What are the official seed nodes?
A: NYC:       138.197.68.128:8444   (Primary)
   London:    167.172.56.119:8444   (Europe)
   Singapore: 165.22.103.114:8444   (Asia-Pacific)
   Sydney:    134.199.159.83:8444   (Oceania)
   All launcher scripts connect to these automatically.

================================================================
  SYSTEM REQUIREMENTS
================================================================

- Windows 10 or later (64-bit)
- 4 GB RAM minimum (RandomX mining requires ~2.5 GB)
- 1 GB disk space
- x86_64 (64-bit) processor
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilithion-node.exe       Main node software (mining + wallet)
check-wallet-balance.exe Check your DIL balance

START-MINING.bat         One-click mining launcher
SETUP-AND-START.bat      Interactive setup wizard
dilithion-wallet.bat     Wallet launcher script

wallet.html              Web wallet interface

README.txt               This file

================================================================
  WINDOWS DEFENDER / ANTIVIRUS
================================================================

Some antivirus software may flag the mining binary because it
uses RandomX (a CPU mining algorithm). This is a false positive.

If Windows Defender blocks the binary:
1. Open Windows Security
2. Go to Virus & threat protection
3. Click "Protection history"
4. Find the blocked item and click "Allow"

Or add the dilithion folder to your exclusions list.

================================================================
  NEED HELP?
================================================================

Website:        https://dilithion.org
Telegram:       https://t.me/dilithion
Source Code:    https://github.com/dilithion/dilithion
Report bugs:    https://github.com/dilithion/dilithion/issues

================================================================
  QUANTUM-RESISTANT CRYPTOGRAPHY
================================================================

Dilithion protects against "Capture Now, Decrypt Later" attacks
where adversaries record encrypted data today to decrypt it when
quantum computers become available.

By using NIST-standardized post-quantum cryptography (FIPS 204),
Dilithion ensures your transactions remain secure even in a
future with powerful quantum computers.

================================================================

Happy mining!

The Dilithion Team
https://dilithion.org

================================================================
