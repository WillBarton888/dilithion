================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  TESTNET RELEASE v1.0.0 - LINUX
================================================================

Welcome to Dilithion!

This is the TESTNET version. Testnet coins have NO monetary value.
They are for testing only.

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

Before running Dilithion, install the required libraries:

UBUNTU / DEBIAN:
  sudo apt-get update
  sudo apt-get install libleveldb-dev libsnappy-dev

FEDORA / RHEL / CENTOS:
  sudo dnf install leveldb-devel snappy-devel

ARCH LINUX:
  sudo pacman -S leveldb snappy

OPENSUSE:
  sudo zypper install leveldb-devel libsnappy-devel

These libraries are required for the blockchain database.

================================================================
  GETTING STARTED - THREE EASY WAYS
================================================================

OPTION 1: ONE-CLICK MINING (Easiest!)
---------------------------------------
1. Open terminal in this directory
2. Run: ./start-mining.sh
3. You're mining!

That's it! The script automatically:
  - Connects to the official seed node
  - Detects your CPU cores
  - Starts mining testnet DIL


OPTION 2: INTERACTIVE SETUP WIZARD
---------------------------------------
1. Open terminal in this directory
2. Run: ./setup-and-start.sh
3. Follow the on-screen instructions
4. Choose how many CPU cores to use
5. Start mining!

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
  FIRST TIME SETUP
================================================================

The scripts handle permissions automatically, but if you need
to make the binaries executable manually:

  chmod +x dilithion-node
  chmod +x check-wallet-balance
  chmod +x start-mining.sh
  chmod +x setup-and-start.sh

================================================================
  HOW TO STOP MINING
================================================================

Press Ctrl+C in the terminal where the miner is running.

The node will shut down gracefully.

================================================================
  WHAT TO EXPECT WHEN MINING
================================================================

When you start mining, you'll see:

1. CONNECTION MESSAGES
   - "Connected to peer: 170.64.203.134:18444"
   - This means you've connected to the official seed node

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
   and won't harm your computer. You can stop it anytime with
   Ctrl+C.

Q: Can I run this on a server?
A: Yes! For headless servers, use:
   ./dilithion-node --testnet --mine --threads=auto

   Or run in screen/tmux to keep it running after logout.

Q: What's the official seed node?
A: 170.64.203.134:18444
   All launcher scripts connect to this automatically.

================================================================
  SYSTEM REQUIREMENTS
================================================================

- Linux kernel 3.2+ (Ubuntu 16.04+, Debian 9+, CentOS 7+, etc.)
- 2 GB RAM minimum (4 GB recommended)
- 1 GB disk space
- x86_64 (64-bit) processor
- Internet connection

================================================================
  FILES IN THIS PACKAGE
================================================================

dilithion-node           Main node software (mining + wallet)
check-wallet-balance     Check your testnet DIL balance
genesis_gen              Genesis block generator (advanced)

start-mining.sh          One-click mining launcher
setup-and-start.sh       Interactive setup wizard

README-LINUX.txt         This file
TESTNET-GUIDE.md         Detailed testnet documentation

================================================================
  RUNNING AS A SERVICE (OPTIONAL)
================================================================

To run Dilithion as a systemd service:

1. Create service file:
   sudo nano /etc/systemd/system/dilithion.service

2. Add this content:
   [Unit]
   Description=Dilithion Testnet Node
   After=network.target

   [Service]
   Type=simple
   User=YOUR_USERNAME
   WorkingDirectory=/path/to/dilithion
   ExecStart=/path/to/dilithion/dilithion-node --testnet --mine
   Restart=always

   [Install]
   WantedBy=multi-user.target

3. Enable and start:
   sudo systemctl enable dilithion
   sudo systemctl start dilithion

4. Check status:
   sudo systemctl status dilithion

5. View logs:
   sudo journalctl -u dilithion -f

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

1. Start mining with ./start-mining.sh
2. Let it run for a while (at least 30 minutes)
3. Check your balance with ./check-wallet-balance
4. Experiment with the software
5. Report any bugs you find!

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
