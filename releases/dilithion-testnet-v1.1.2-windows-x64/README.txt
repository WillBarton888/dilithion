================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  TESTNET RELEASE v1.0.0 - WINDOWS
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
  GETTING STARTED - THREE EASY WAYS
================================================================

OPTION 1: ONE-CLICK MINING (Easiest!)
---------------------------------------
1. Double-click: START-MINING.bat
2. Wait a few seconds
3. You're mining!

That's it! The script automatically:
  - Connects to the official seed node
  - Detects your CPU cores
  - Starts mining testnet DIL


OPTION 2: INTERACTIVE SETUP WIZARD
---------------------------------------
1. Double-click: SETUP-AND-START.bat
2. Follow the on-screen instructions
3. Choose how many CPU cores to use
4. Start mining!

This wizard walks you through each step and explains
what each setting does.


OPTION 3: ADVANCED (Command Line)
---------------------------------------
1. Open Command Prompt (cmd.exe)
2. Navigate to this folder:
   cd C:\path\to\dilithion
3. Run with no arguments for auto-start:
   dilithion-node.exe

   Or customize with arguments:
   dilithion-node.exe --testnet --mine --threads=4

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
A: Run: check-wallet-balance.exe
   This shows your testnet DIL balance.

Q: Is this safe?
A: Testnet mining is safe. It only uses CPU (no GPU needed)
   and won't harm your computer. The miner runs in a normal
   window you can close anytime.

Q: Can I mine on a laptop?
A: Yes, but laptops may get warm. Use the wizard to choose
   1-2 cores for light mining. Desktop PCs handle mining better.

Q: What are the official seed nodes?
A: NYC: 134.122.4.164:18444 (Primary)
   Singapore: 188.166.255.63:18444 (Asia-Pacific)
   London: 209.97.177.197:18444 (Europe)
   All launcher scripts connect to these automatically.

================================================================
  FILES IN THIS PACKAGE
================================================================

dilithion-node.exe       Main node software (mining + wallet)
check-wallet-balance.exe Check your testnet DIL balance
genesis_gen.exe          Genesis block generator (advanced)

START-MINING.bat         One-click mining launcher
SETUP-AND-START.bat      Interactive setup wizard

README-WINDOWS.txt       This file
TESTNET-GUIDE.md         Detailed testnet documentation

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

1. Start mining with START-MINING.bat
2. Let it run for a while (at least 30 minutes)
3. Check your balance with check-wallet-balance.exe
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
