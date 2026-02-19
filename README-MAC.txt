================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  MAINNET RELEASE - macOS
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
  INSTALL DEPENDENCIES (REQUIRED FIRST!)
================================================================

Before running Dilithion, install Homebrew and LevelDB:

1. Install Homebrew (if not already installed):
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

2. Install LevelDB:
   brew install leveldb

This database library is required for the blockchain storage.

================================================================
  GETTING STARTED - THREE EASY WAYS
================================================================

OPTION 1: INTERACTIVE SETUP WIZARD (Recommended for first time!)
---------------------------------------
1. Open Terminal (Applications > Utilities > Terminal)
2. Navigate to this folder:
   cd ~/Downloads/dilithion-macos
   (or wherever you extracted the files)
3. Run: ./setup-and-start.sh
4. Follow the on-screen instructions

The wizard will:
  - Offer to download a blockchain snapshot for fast sync
  - Let you choose how many CPU cores to use
  - Start mining automatically


OPTION 2: ONE-CLICK MINING (Quick start)
---------------------------------------
1. Open Terminal
2. Navigate to this folder
3. Run: ./start-mining.sh
4. You're mining!

The script automatically:
  - Connects to the official seed nodes
  - Detects your CPU cores
  - Starts mining DIL


OPTION 3: ADVANCED (Command Line)
---------------------------------------
Run with no arguments for auto-start:
  ./dilithion-node

Or customize with arguments:
  ./dilithion-node --mine --threads=4

For all options:
  ./dilithion-node --help

================================================================
  FIRST TIME SETUP - IMPORTANT FOR macOS
================================================================

macOS SECURITY WARNING:

When you first run the binaries, macOS Gatekeeper may block
them because they're not from the App Store or a verified
developer.

TO FIX THIS:

Method 1 (Easiest):
1. Right-click the file (dilithion-node)
2. Select "Open"
3. Click "Open" in the security dialog
4. Repeat for each binary that gets blocked

Method 2 (Command Line):
  xattr -d com.apple.quarantine dilithion-node
  xattr -d com.apple.quarantine check-wallet-balance
  xattr -d com.apple.quarantine start-mining.sh
  xattr -d com.apple.quarantine setup-and-start.sh

Method 3 (Allow in System Settings):
1. Try to run the binary
2. Go to System Settings > Privacy & Security
3. Click "Allow Anyway" for the blocked app
4. Try running again

PERMISSIONS:

Make scripts executable if needed:
  chmod +x dilithion-node
  chmod +x check-wallet-balance
  chmod +x start-mining.sh
  chmod +x setup-and-start.sh

================================================================
  HOW TO STOP MINING
================================================================

Press Ctrl+C (or Command+C) in the Terminal where the miner
is running.

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
A: Run: ./check-wallet-balance
   This shows your DIL balance.

Q: Is mining safe for my Mac?
A: Mining is safe. It uses CPU only (no GPU needed) and won't
   harm your Mac. You can stop it anytime with Ctrl+C.
   Note: RandomX mining uses ~2.5 GB RAM.

Q: Will this work on Apple Silicon (M1/M2/M3/M4)?
A: This binary is compiled for x86_64 (Intel). It will run on
   Apple Silicon Macs through Rosetta 2 translation, but may be
   slower. Native ARM64 builds are planned.

Q: Can I mine on a MacBook?
A: Yes, but MacBooks may get warm. Use the wizard to choose
   1-2 cores for light mining. Mac desktops (iMac, Mac Studio)
   handle mining better.

Q: What are the official seed nodes?
A: NYC:       138.197.68.128:8444   (Primary)
   London:    167.172.56.119:8444   (Europe)
   Singapore: 165.22.103.114:8444   (Asia-Pacific)
   Sydney:    134.199.159.83:8444   (Oceania)
   All launcher scripts connect to these automatically.

================================================================
  SYSTEM REQUIREMENTS
================================================================

- macOS 10.13 (High Sierra) or later
- 4 GB RAM minimum (RandomX mining requires ~2.5 GB)
- 1 GB disk space
- Intel or Apple Silicon processor
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilithion-node           Main node software (mining + wallet)
check-wallet-balance     Check your DIL balance
genesis_gen              Genesis block generator (advanced)

start-mining.sh          One-click mining launcher
setup-and-start.sh       Interactive setup wizard

README.txt               This file

================================================================
  RUNNING IN BACKGROUND (OPTIONAL)
================================================================

To keep mining when you close Terminal:

1. Install screen or tmux (using Homebrew):
   brew install screen

2. Start a screen session:
   screen -S dilithion

3. Run the miner:
   ./start-mining.sh

4. Detach with: Ctrl+A, then D

5. Reattach anytime with:
   screen -r dilithion

Alternatively, use nohup:
  nohup ./dilithion-node --mine &

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
