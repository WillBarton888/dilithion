Dilithion Testnet v1.1.15 - macOS x64
=====================================

WHAT'S NEW IN v1.1.15:
- FIX: Web wallet logo now displays correctly (inline SVG)
- FIX: Block hash no longer overlaps with difficulty display
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
1. Open Terminal in this directory
2. Run: chmod +x dilithion-node check-wallet-balance start-mining.sh
3. Run: ./start-mining.sh
4. On first run, WRITE DOWN your 24-word recovery phrase
5. Type 'Y' to confirm you've saved it

WEB WALLET:
Once the node is running, open your browser to:
  http://localhost:18334/wallet

FILES INCLUDED:
- dilithion-node       - Main node (mining, sync, RPC, HTTP server)
- check-wallet-balance - Quick balance checker
- start-mining.sh      - One-click mining launcher
- setup-and-start.sh   - Interactive setup wizard
- wallet.html          - Standalone web wallet (optional)
- README.txt           - This file
- TESTNET-GUIDE.md     - Detailed testnet documentation

DEPENDENCIES:
You may need to install LevelDB:
  brew install leveldb

MACOS GATEKEEPER:
If you see "cannot be verified" warning:
  Right-click file -> Open, or
  System Settings -> Privacy & Security -> Allow Anyway

TESTNET INFO:
- Coins have NO monetary value
- P2P Port: 18444
- RPC Port: 18332
- HTTP/Web Port: 18334

Website: https://dilithion.org
GitHub:  https://github.com/WillBarton888/dilithion
