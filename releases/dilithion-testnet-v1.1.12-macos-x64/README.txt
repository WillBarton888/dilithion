================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  TESTNET RELEASE v1.1.12 - macOS
================================================================

WHAT'S NEW IN v1.1.12:
- NEW: Web Wallet accessible at http://localhost:18334/wallet
- Web wallet embedded in node binary - works on all platforms
- CORS support for browser-based wallet access
- HD wallet improvements for mined block rewards

Welcome to Dilithion!

This is the TESTNET version. Testnet coins have NO monetary value.
They are for testing only.

================================================================
  WEB WALLET (NEW IN v1.1.12!)
================================================================

Once the node is running, open your browser to:
  http://localhost:18334/wallet

The web wallet is embedded directly in the node binary!
No external files needed. Works on all platforms.

Or open wallet.html for standalone use with manual RPC config.

================================================================
  WHAT IS DILITHION?
================================================================

Dilithion is a post-quantum cryptocurrency that uses NIST-
standardized cryptography (CRYSTALS-Dilithium, SHA-3) to protect
against future quantum computer attacks.

This testnet allows you to:
  - Test mining Dilithion coins (testnet DIL)
  - Experiment with the wallet
  - Help us find bugs before mainnet launch

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

OPTION 1: ONE-CLICK MINING (Easiest!)
---------------------------------------
1. Open Terminal (Applications > Utilities > Terminal)
2. Navigate to this folder:
   cd ~/Downloads/dilithion-testnet-macos
   (or wherever you extracted the files)
3. Run: ./start-mining.sh
4. You're mining!

That's it! The script automatically:
  - Connects to the official seed node
  - Detects your CPU cores
  - Starts mining testnet DIL


OPTION 2: INTERACTIVE SETUP WIZARD
---------------------------------------
1. Open Terminal
2. Navigate to this folder
3. Run: ./setup-and-start.sh
4. Follow the on-screen instructions
5. Choose how many CPU cores to use
6. Start mining!

This wizard walks you through each step and explains
what each setting does.


OPTION 3: ADVANCED (Command Line)
---------------------------------------
Run with no arguments for auto-start:
  ./dilithion-node

Or customize with arguments:
  ./dilithion-node --testnet --mine --threads=4

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

Method 3 (Allow in System Preferences):
1. Try to run the binary
2. Go to System Preferences > Security & Privacy
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
   - "Connected to peer: 134.122.4.164:18444" (or Singapore/London)
   - This means you've connected to one of the official seed nodes

2. BLOCKCHAIN SYNC
   - "Downloading blocks..."
   - Your node catches up to the latest block

3. MINING MESSAGES
   - "Mining block at height XXXXX..."
   - "Block found! Hash: 00000..."
   - Your CPU is trying to find new blocks

4. NETWORK ACTIVITY
   - Messages about peers connecting/disconnecting
   - New transactions received
   - New blocks discovered by other miners

================================================================
  FREQUENTLY ASKED QUESTIONS
================================================================

Q: How long until I mine a block?
A: Testnet difficulty is LOW (256x easier than mainnet).
   Depending on your CPU and network hashrate, you might find
   blocks in minutes to hours. Mainnet will be much harder!

Q: Do testnet coins have value?
A: NO! Testnet DIL has zero monetary value. They are for
   testing only. The mainnet will launch later with real coins.

Q: How do I check my balance?
A: Run: ./check-wallet-balance
   This shows your testnet DIL balance.

Q: Is this safe?
A: Testnet mining is safe. It only uses CPU (no GPU needed)
   and won't harm your Mac. You can stop it anytime with Ctrl+C.

Q: Will this work on Apple Silicon (M1/M2/M3)?
A: This binary is compiled for x86_64 (Intel). It will run on
   Apple Silicon Macs through Rosetta 2 translation, but may be
   slower. We're working on native ARM64 binaries for Apple
   Silicon.

Q: Can I mine on a MacBook?
A: Yes, but MacBooks may get warm. Use the wizard to choose
   1-2 cores for light mining. Mac desktops (iMac, Mac Studio)
   handle mining better.

Q: What are the official seed nodes?
A: NYC: 134.122.4.164:18444 (Primary)
   Singapore: 188.166.255.63:18444 (Asia-Pacific)
   London: 209.97.177.197:18444 (Europe)
   All launcher scripts connect to these automatically.

================================================================
  SYSTEM REQUIREMENTS
================================================================

- macOS 10.13 (High Sierra) or later
- 2 GB RAM minimum (4 GB recommended)
- 1 GB disk space
- Intel or Apple Silicon processor
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilithion-node           Main node software (mining + wallet + HTTP server)
check-wallet-balance     Check your testnet DIL balance
wallet.html              Standalone web wallet (optional)

start-mining.sh          One-click mining launcher
setup-and-start.sh       Interactive setup wizard

README.txt               This file
TESTNET-GUIDE.md         Detailed testnet documentation

PORTS:
- P2P Port: 18444 (peer network)
- RPC Port: 18332 (JSON-RPC API)
- HTTP Port: 18334 (Web wallet)

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
  nohup ./dilithion-node --testnet --mine &

================================================================
  NEED HELP?
================================================================

Website:        https://dilithion.org
Documentation:  https://github.com/WillBarton888/dilithion
Testnet Guide:  See TESTNET-GUIDE.md in this folder

Report bugs:    https://github.com/WillBarton888/dilithion/issues

================================================================
  SECURITY NOTE
================================================================

IMPORTANT: This is TESTNET software. Do NOT use testnet wallets
or addresses for real value. When mainnet launches, you'll need
to create a new wallet.

The testnet uses different network ports and a different genesis
block than mainnet. They are completely separate networks.

================================================================
  WHAT'S NEXT?
================================================================

1. Bypass macOS security (see "FIRST TIME SETUP" above)
2. Start mining with ./start-mining.sh
3. Let it run for a while (at least 30 minutes)
4. Check your balance with ./check-wallet-balance
5. Experiment with the software
6. Report any bugs you find!

Thank you for helping test Dilithion!

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
