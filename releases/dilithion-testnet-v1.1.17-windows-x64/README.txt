Dilithion Testnet v1.1.17 - Windows x64
======================================

WHAT'S NEW IN v1.1.17:
- FIX: Confirmation dialog now works in standalone wallet.html
- Shows amount, fee, and total before sending
- Requires explicit confirmation before transaction

WHAT'S NEW IN v1.1.16:
- NEW: Send confirmation dialog in web wallet
- Shows transaction details before sending

WHAT'S NEW IN v1.1.15:
- FIX: Web wallet logo now displays correctly (actual Dilithion lion shield)
- FIX: Block hash no longer overlaps with difficulty display
- FIX: Send transaction now works correctly in web wallet
- UI improvements to Blockchain Status page

WHAT'S NEW IN v1.1.14:
- FIX: Web wallet now correctly shows immature balance (mined coins)
- Total balance now includes immature + confirmed + unconfirmed

WHAT'S NEW IN v1.1.13:
- FIX: Web wallet now correctly shows "Testnet" instead of "Mainnet"
- Fixed getblockchaininfo RPC to return correct chain type

WHAT'S NEW IN v1.1.12:
- NEW: Web Wallet accessible at http://localhost:18334/wallet
- Web wallet embedded in node binary - works on all platforms
- CORS support for browser-based wallet access
- HD wallet improvements for mined block rewards

QUICK START:
1. Double-click START-MINING.bat
2. On first run, WRITE DOWN your 24-word recovery phrase on paper
3. Type 'Y' to confirm you've saved it
4. The node will sync with the network, then start mining

WEB WALLET:
Once the node is running, open your browser to:
  http://localhost:18334/wallet

Or open wallet.html directly for manual RPC connection.

FILES INCLUDED:
- dilithion-node.exe    - Main node (mining, sync, RPC, HTTP server)
- check-wallet-balance.exe - Quick balance checker
- wallet.html           - Standalone web wallet (optional)
- START-MINING.bat      - Easy start script
- dilithion-wallet.bat  - Wallet management menu
- SETUP-AND-START.bat   - First-time setup wizard
- *.dll                 - Required libraries

RECOVERY PHRASE:
Your 24-word phrase is your ONLY backup. Store it on PAPER.
Never share it. Never store it digitally.

TESTNET INFO:
- Coins have NO monetary value
- P2P Port: 18444
- RPC Port: 18332
- HTTP/Web Port: 18334

Website: https://dilithion.org
GitHub:  https://github.com/WillBarton888/dilithion
