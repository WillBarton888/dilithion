Dilithion Testnet v1.1.20 - Windows x64
======================================

WHAT'S NEW IN v1.1.20:
- CRITICAL FIX: P2P zombie peer bug causing connection exhaustion (BUG #105)
- Fixed handshake failures leaving peers in memory without cleanup
- Fixed connection limit check to count only connected peers
- Fixed cooldown timestamp only set after successful connection
- Added logging for connection rejection reasons
- Peers should now maintain stable connections

WHAT'S NEW IN v1.1.19:
- FIX: Web wallet now displays sent transactions in history (BUG #104 complete)
- Sent transactions show with red icon and negative amount
- Transaction history sorted by time (newest first)

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
