================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  MAINNET RELEASE - LINUX
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

Before running Dilithion, install the required libraries:

UBUNTU / DEBIAN:
  sudo apt-get update
  sudo apt-get install libleveldb-dev libsnappy-dev

FEDORA / RHEL / CENTOS:
  sudo dnf install leveldb-devel snappy-devel

ARCH LINUX:
  sudo pacman -S leveldb snappy

ALPINE LINUX:
  sudo apk add leveldb-dev snappy-dev

OPENSUSE:
  sudo zypper install leveldb-devel libsnappy-devel

These libraries are required for the blockchain database.

================================================================
  GETTING STARTED - THREE EASY WAYS
================================================================

OPTION 1: INTERACTIVE SETUP WIZARD (Recommended for first time!)
---------------------------------------
1. Open terminal in this directory
2. Run: ./setup-and-start.sh
3. Follow the on-screen instructions

The wizard will:
  - Offer to download a blockchain snapshot for fast sync
  - Let you choose how many CPU cores to use
  - Start mining automatically

OPTION 2: ONE-CLICK MINING (Quick start)
---------------------------------------
1. Open terminal in this directory
2. Run: ./start-mining.sh
3. You're mining!

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

Q: Is mining safe for my computer?
A: Mining is safe. It uses CPU only (no GPU needed) and won't
   harm your computer. You can stop it anytime with Ctrl+C.
   Note: RandomX mining uses ~2.5 GB RAM.

Q: Can I run this on a server?
A: Yes! For headless servers, use:
   ./dilithion-node --mine --threads=auto

   Or run in screen/tmux to keep it running after logout.

Q: What are the official seed nodes?
A: NYC:       138.197.68.128:8444   (Primary)
   London:    167.172.56.119:8444   (Europe)
   Singapore: 165.22.103.114:8444   (Asia-Pacific)
   Sydney:    134.199.159.83:8444   (Oceania)
   All launcher scripts connect to these automatically.

================================================================
  SYSTEM REQUIREMENTS
================================================================

- Linux kernel 3.2+ (Ubuntu 18.04+, Debian 10+, CentOS 7+, etc.)
- 4 GB RAM minimum (RandomX mining requires ~2.5 GB)
- 1 GB disk space
- x86_64 (64-bit) processor
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
  RUNNING AS A SERVICE (OPTIONAL)
================================================================

To run Dilithion as a systemd service:

1. Create service file:
   sudo nano /etc/systemd/system/dilithion.service

2. Add this content:
   [Unit]
   Description=Dilithion Mainnet Node
   After=network.target

   [Service]
   Type=simple
   User=YOUR_USERNAME
   WorkingDirectory=/path/to/dilithion
   ExecStart=/path/to/dilithion/dilithion-node --mine
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
