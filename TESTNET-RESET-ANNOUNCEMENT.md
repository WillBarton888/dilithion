# Testnet Reset Announcement Template

Use this template to notify your testnet community about the reset. Customize the dates, times, and contact information as needed.

---

## 📢 ANNOUNCEMENT (7 Days Before Reset)

```
🔴 IMPORTANT: DILITHION TESTNET RESET SCHEDULED 🔴

Dear Dilithion Testnet Community,

We will be resetting the testnet on [DATE] at [TIME UTC] to implement Chain ID
(EIP-155) replay protection - a critical security feature for mainnet launch.

═══════════════════════════════════════════════════════════════════

📋 WHAT'S CHANGING

• Transaction signature format upgraded (40 → 44 bytes)
• Chain ID enforcement (testnet = 1001, mainnet = 1)
• Prevents cross-chain replay attacks between mainnet/testnet
• Follows Ethereum EIP-155 security standard

═══════════════════════════════════════════════════════════════════

⚠️  BREAKING CHANGES

• ALL existing testnet wallets will be INVALID
• ALL existing testnet DIL will be LOST (no real value)
• Old and new nodes CANNOT interoperate
• Network will be completely reset from genesis block 0

═══════════════════════════════════════════════════════════════════

✅ WHAT YOU NEED TO DO

BEFORE RESET (Do this NOW):
  ✓ Backup important test data/transaction IDs for analysis
  ✓ Save wallet addresses for reference (keys won't work after)
  ✓ Document any ongoing tests or experiments
  ✓ Update your node software to latest version

DURING RESET ([DATE] at [TIME UTC]):
  ✓ Stop your testnet node
  ✓ Delete ~/.dilithion-testnet directory
  ✓ Wait for new genesis parameters announcement

AFTER RESET:
  ✓ Start node with updated software
  ✓ Create NEW wallet (old wallets incompatible)
  ✓ Resume testing with chain ID protection active

═══════════════════════════════════════════════════════════════════

📅 TIMELINE

[DATE - 7 days]:  This announcement
[DATE - 3 days]:  Reminder + technical Q&A session
[DATE - 1 day]:   Final reminder + shutdown procedures
[DATE]:           Network shutdown at [TIME UTC]
[DATE + 1 hour]:  New testnet genesis mined
[DATE + 2 hours]: New testnet launches

═══════════════════════════════════════════════════════════════════

🔧 TECHNICAL DETAILS

WHY THIS IS NECESSARY:
Chain ID prevents replay attacks. Without it, a transaction signed on testnet
could be replayed on mainnet, causing users to lose real funds on both chains.

OLD SIGNATURE FORMAT (40 bytes):
  tx_hash (32B) + input_index (4B) + version (4B)
  → Works on ANY network ❌

NEW SIGNATURE FORMAT (44 bytes):
  tx_hash (32B) + input_index (4B) + version (4B) + chain_id (4B)
  → Network-specific signatures ✅

SECURITY IMPROVEMENTS:
  ✅ Testnet signatures include chain_id = 1001
  ✅ Mainnet signatures include chain_id = 1
  ✅ Cross-network replay prevented cryptographically
  ✅ Future fork protection built-in

═══════════════════════════════════════════════════════════════════

📖 DOCUMENTATION

Complete guides available in repository:
• TESTNET-RESET-GUIDE.md - Step-by-step reset instructions
• CHAIN-ID-IMPLEMENTATION.md - Technical specification
• PHASE-5-TRANSACTION-UTXO-AUDIT.md - Security audit findings

═══════════════════════════════════════════════════════════════════

❓ FREQUENTLY ASKED QUESTIONS

Q: Will mainnet require a similar reset?
A: No. Mainnet hasn't launched yet, so chain ID will be included from genesis.

Q: Can I keep my old testnet wallet?
A: No. Signature format changed, making old wallets incompatible.

Q: What if I miss the reset window?
A: No problem. Follow the reset guide whenever you're ready to rejoin.

Q: Will there be more testnet resets?
A: Only for major protocol changes. This is expected on testnet.

Q: Can I run old and new nodes together?
A: No. They use incompatible signature formats and will reject each other.

Q: How do I verify my node has chain ID support?
A: Run: git log --oneline | grep "513937e"
   You should see the chain ID commit.

═══════════════════════════════════════════════════════════════════

💬 GET HELP

Questions? Concerns? Join the discussion:
• GitHub: [YOUR_REPO_URL]/issues
• Discord: [YOUR_DISCORD_LINK]
• Telegram: [YOUR_TELEGRAM_LINK]
• Email: [YOUR_EMAIL]

═══════════════════════════════════════════════════════════════════

🙏 THANK YOU

Thank you for being part of the Dilithion testnet! Your testing helps us
build a more secure and robust cryptocurrency for everyone.

This reset is a necessary step to ensure mainnet launches with the strongest
possible replay attack protection.

See you on the new testnet!

- The Dilithion Core Development Team

═══════════════════════════════════════════════════════════════════
```

---

## 📢 REMINDER (3 Days Before Reset)

```
⏰ REMINDER: TESTNET RESET IN 3 DAYS ⏰

Dilithion Testnet Reset: [DATE] at [TIME UTC]

QUICK CHECKLIST:

Today (3 days before):
  □ Have you backed up important test data?
  □ Have you updated to the latest node software?
  □ Have you read the TESTNET-RESET-GUIDE.md?

On reset day:
  □ Stop your node
  □ Delete ~/.dilithion-testnet
  □ Wait for new genesis parameters

After reset:
  □ Start node with --testnet flag
  □ Create new wallet

═══════════════════════════════════════════════════════════════════

TECHNICAL Q&A SESSION:

Join us for a live Q&A session to discuss the reset:
• Date: [DATE]
• Time: [TIME UTC]
• Where: [DISCORD/ZOOM/TELEGRAM LINK]

Topics:
- Chain ID implementation details
- Reset procedures walkthrough
- Troubleshooting common issues
- Mainnet launch timeline

═══════════════════════════════════════════════════════════════════

QUESTIONS? Reply to this message or join our community channels.

- The Dilithion Team
```

---

## 📢 FINAL REMINDER (1 Day Before Reset)

```
🚨 FINAL REMINDER: TESTNET RESET TOMORROW 🚨

TESTNET RESET: [DATE] at [TIME UTC]
TIME REMAINING: Less than 24 hours!

═══════════════════════════════════════════════════════════════════

TOMORROW'S SCHEDULE (All times UTC):

[TIME - 1 hour]:  Final call - make backups now
[TIME]:           Network shutdown begins
[TIME + 30 min]:  All nodes should be stopped
[TIME + 1 hour]:  Genesis mining begins
[TIME + 2 hours]: New testnet launches (estimated)

═══════════════════════════════════════════════════════════════════

RESET CHECKLIST:

1. STOP your testnet node:
   pkill dilithion-node

2. DELETE testnet data:
   rm -rf ~/.dilithion-testnet

3. UPDATE your software:
   git pull origin main
   make clean && make

4. WAIT for new genesis announcement (will be posted here)

5. START with new genesis:
   ./dilithion-node --testnet

═══════════════════════════════════════════════════════════════════

SEED NODE INFORMATION:

After reset, connect to the official seed node:
• IP: [SEED_NODE_IP]
• Port: 18444 (testnet default)
• Command: ./dilithion-node --testnet --addnode=[SEED_NODE_IP]:18444

═══════════════════════════════════════════════════════════════════

NEW GENESIS PARAMETERS:

Will be announced at [TIME + 1 hour] after successful mining.
Watch this channel for updates!

Parameters to watch for:
• Genesis Time
• Genesis Nonce
• Genesis Hash
• Chain ID: 1001 (confirmed)

═══════════════════════════════════════════════════════════════════

NEED HELP? We'll be monitoring all channels during the reset.

- The Dilithion Team
```

---

## 📢 RESET COMPLETE (After Reset)

```
✅ TESTNET RESET COMPLETE ✅

The Dilithion testnet has been successfully reset with Chain ID protection!

═══════════════════════════════════════════════════════════════════

🎉 NEW GENESIS PARAMETERS

Network:        TESTNET
Chain ID:       1001 ✅
Genesis Time:   [ACTUAL_TIME]
Genesis Nonce:  [ACTUAL_NONCE]
Genesis Hash:   [ACTUAL_HASH]
Genesis nBits:  0x1f060000
Network Magic:  0xDAB5BFFA

═══════════════════════════════════════════════════════════════════

🚀 START YOUR NODE

Update chainparams.cpp with new genesis:

```cpp
ChainParams ChainParams::Testnet() {
    ChainParams params;
    params.network = TESTNET;
    params.networkMagic = 0xDAB5BFFA;
    params.chainID = 1001;

    params.genesisTime = [ACTUAL_TIME];
    params.genesisNonce = [ACTUAL_NONCE];
    params.genesisNBits = 0x1f060000;
    params.genesisHash = "[ACTUAL_HASH]";
    params.genesisCoinbaseMsg = "Dilithion Testnet Reset - Chain ID Implementation [DATE]";

    // ... rest of params ...
}
```

Rebuild and start:
```bash
make clean && make
./dilithion-node --testnet --mine --threads=auto
```

═══════════════════════════════════════════════════════════════════

📊 NETWORK STATUS

Block Height:    [CURRENT_HEIGHT]
Connected Peers: [PEER_COUNT]
Hash Rate:       [HASH_RATE]
Chain ID:        1001 ✅ VERIFIED

Seed Nodes:
• [SEED_NODE_1]
• [SEED_NODE_2]

═══════════════════════════════════════════════════════════════════

💰 CREATE NEW WALLET

All old wallets are invalid. Create a new one:

```bash
./dilithion-wallet --testnet create
./dilithion-wallet --testnet getnewaddress
```

═══════════════════════════════════════════════════════════════════

✅ VERIFICATION

Verify chain ID is active:

1. Check node output on startup:
   Should see: "Chain ID: 1001"

2. Verify genesis hash:
   ./dilithion-cli --testnet getblockhash 0
   Should match: [ACTUAL_HASH]

3. Test transaction:
   Create and send a test transaction
   Signature should be 44 bytes with chain ID

═══════════════════════════════════════════════════════════════════

📈 WHAT'S NEXT

Now that testnet has chain ID protection:
• Continue normal testing
• Test cross-chain isolation (if you're technical)
• Prepare for mainnet launch
• Report any issues

═══════════════════════════════════════════════════════════════════

🎯 MAINNET LAUNCH

With chain ID implementation complete, we're one step closer to mainnet!

Remaining milestones:
• Final security audits
• Load testing at scale
• Wallet software finalization
• Exchange integrations

Estimated mainnet launch: [YOUR_ESTIMATE]

═══════════════════════════════════════════════════════════════════

Thank you for your patience during the reset!

Happy testing! 🚀

- The Dilithion Team
```

---

## Social Media Templates

### Twitter/X

```
🔴 TESTNET RESET ALERT

@DilithionCoin testnet resets [DATE] for Chain ID implementation (EIP-155).

✅ Prevents replay attacks
❌ Old wallets invalid
📖 Guide: [LINK]

Testing the future of post-quantum crypto!

#Dilithion #PostQuantum #CryptoSecurity
```

### Discord Announcement

```
@everyone

🔴 **TESTNET RESET SCHEDULED** 🔴

**Date:** [DATE] at [TIME UTC]
**Reason:** Chain ID (EIP-155) implementation

**What you need to do:**
1. Backup test data
2. Stop node on [DATE]
3. Delete `~/.dilithion-testnet`
4. Wait for new genesis
5. Restart with fresh wallet

**Why:** Prevents replay attacks between mainnet/testnet

**Docs:** Check pinned messages for full guide

React with ✅ if you've read this!
```

---

## Email Template

```
Subject: [ACTION REQUIRED] Dilithion Testnet Reset - [DATE]

Dear Testnet Participant,

This is an important notification about an upcoming testnet reset.

TESTNET RESET DETAILS:
------------------------------
Date: [DATE]
Time: [TIME UTC]
Reason: Chain ID Implementation (Security Upgrade)

REQUIRED ACTIONS:
------------------------------
Before Reset:
☐ Backup any important test data
☐ Update to latest node software

On Reset Day:
☐ Stop your testnet node
☐ Delete ~/.dilithion-testnet directory
☐ Wait for new genesis parameters

After Reset:
☐ Start node with updated software
☐ Create new wallet

WHAT'S CHANGING:
------------------------------
We're implementing Chain ID (EIP-155) replay protection, which prevents
transactions from being replayed between testnet and mainnet. This is a
critical security feature that must be in place before mainnet launch.

Technical Details:
• Signature format: 40 bytes → 44 bytes (adds chain ID)
• Testnet Chain ID: 1001
• Mainnet Chain ID: 1

DOCUMENTATION:
------------------------------
Complete guides are available in our repository:
[GITHUB_REPO_URL]

• TESTNET-RESET-GUIDE.md
• CHAIN-ID-IMPLEMENTATION.md

SUPPORT:
------------------------------
Questions? Contact us:
• GitHub Issues: [URL]
• Discord: [URL]
• Email: [EMAIL]

Thank you for participating in Dilithion testnet!

Best regards,
The Dilithion Core Team

---
Dilithion: Post-Quantum Cryptocurrency
[WEBSITE] | [GITHUB] | [DISCORD]
```

---

**Usage Instructions:**

1. Copy the appropriate template above
2. Replace all [PLACEHOLDER] values with actual information
3. Customize contact links and branding
4. Post to your community channels 7 days before reset
5. Follow up with reminder messages at 3 days and 1 day before
6. Announce completion with actual genesis parameters

**Tone Guidelines:**
- Be clear and direct about breaking changes
- Emphasize security benefits
- Acknowledge inconvenience but explain necessity
- Provide actionable steps
- Offer support channels for questions

