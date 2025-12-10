================================================================
  DILITHION - POST-QUANTUM CRYPTOCURRENCY
  TESTNET RELEASE v1.1.6 - WINDOWS
================================================================

Welcome to Dilithion!

This is the TESTNET version. Testnet coins have NO monetary value.
They are for testing only.

================================================================
  WHAT'S NEW IN v1.1.6
================================================================

- Recovery phrase confirmation prompt added
- When creating a new wallet, you must type 'Y' to confirm
  you've saved your 24-word recovery phrase before continuing
- This prevents accidentally losing access to your funds

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

OPTION 3: ADVANCED (Command Line)
---------------------------------------
1. Open Command Prompt (cmd.exe)
2. Navigate to this folder
3. Run: dilithion-node.exe --testnet --mine

   For all options:
   dilithion-node.exe --help

================================================================
  WALLET FEATURES (HD WALLET)
================================================================

Dilithion uses a Hierarchical Deterministic (HD) wallet:

- 24-word recovery phrase (BIP-39 compatible)
- Derive unlimited addresses from one seed
- Backup once, recover everything

IMPORTANT: When you first run the node, it will display your
24-word recovery phrase. WRITE IT DOWN ON PAPER and store it
safely. This is your ONLY backup!

To manage your wallet:
  - Double-click: dilithion-wallet.bat

================================================================
  HOW TO CHECK YOUR BALANCE
================================================================

OPTION 1: Command Line
  Open cmd.exe in this folder and run:
  check-wallet-balance.exe

OPTION 2: Wallet Menu
  Double-click: dilithion-wallet.bat
  Select option to check balance

NOTE: The check-wallet-balance.exe window closes quickly when
double-clicked. Use the command line or wallet menu instead.

================================================================
  FILES IN THIS PACKAGE
================================================================

dilithion-node.exe       Main node software (mining + wallet)
check-wallet-balance.exe Check your testnet DIL balance

START-MINING.bat         One-click mining launcher
SETUP-AND-START.bat      Interactive setup wizard
dilithion-wallet.bat     Wallet management menu

README.txt               This file
TESTNET-GUIDE.md         Detailed testnet documentation

================================================================
  OFFICIAL SEED NODES
================================================================

NYC:       134.122.4.164:18444 (Primary)
Singapore: 188.166.255.63:18444 (Asia-Pacific)
London:    209.97.177.197:18444 (Europe)

All launcher scripts connect to these automatically.

================================================================
  NEED HELP?
================================================================

Website:        https://dilithion.org
Documentation:  https://github.com/WillBarton888/dilithion
Report bugs:    https://github.com/WillBarton888/dilithion/issues

================================================================
  SECURITY NOTE
================================================================

IMPORTANT: This is TESTNET software. Testnet coins have NO value.
When mainnet launches, you'll need to create a new wallet.

================================================================

Happy mining!

The Dilithion Team
https://dilithion.org

================================================================
