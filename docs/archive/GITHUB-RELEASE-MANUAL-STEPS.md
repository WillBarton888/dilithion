# GitHub Release - Manual Steps

GitHub CLI is not installed, so follow these manual steps via web UI.

## Step 1: Create Release via Web UI

1. **Go to releases page:**
   ```
   https://github.com/WillBarton888/dilithion/releases/new
   ```

2. **Fill in the form:**
   - **Tag**: `v1.0-testnet`
   - **Target**: `main` branch
   - **Release title**: `Dilithion v1.0-testnet - Public Testnet Launch`
   - **Description**: Copy entire content from `.github-release-notes.md` file below

3. **Check the box**: ✅ "This is a pre-release"

4. **Click**: "Publish release"

---

## Release Description (Copy This)

```markdown
# 🚀 Dilithion v1.0-testnet - Public Testnet Launch

First public testnet release of Dilithion, a post-quantum cryptocurrency.

## What's New

### Critical Bug Fixes (October 28, 2025)
- ✅ **FIXED**: UTXO serialization format mismatch (consensus-critical)
- ✅ **FIXED**: Wallet unlock for unencrypted wallets
- ✅ **FIXED**: DNS seed node initialization
- ✅ **Test pass rate**: Improved from 79% to 93%

Full details: [DEFICIENCY-FIXES-SUMMARY.md](https://github.com/WillBarton888/dilithion/blob/main/DEFICIENCY-FIXES-SUMMARY.md)

### Features
- CRYSTALS-Dilithium3 post-quantum signatures (NIST-approved)
- RandomX CPU-friendly proof-of-work
- Full UTXO transaction model
- SHA3-256 quantum-resistant hashing
- Comprehensive security hardening (4 phases)

## Getting Started

### Quick Start
```bash
git clone https://github.com/WillBarton888/dilithion.git
cd dilithion
make
./dilithion-node --mine --threads=4
```

### Full Guide
See [TESTNET-LAUNCH.md](https://github.com/WillBarton888/dilithion/blob/main/TESTNET-LAUNCH.md)

## What to Test

- Mining stability (24+ hour tests)
- Wallet operations (create, send, encrypt)
- Network connectivity (peer discovery)
- Transaction validation
- Edge cases and stress testing

## Known Issues

- 1 test with minor non-critical failures (wallet_tests - 2/16 subtests)

## Documentation

- [TESTNET-LAUNCH.md](https://github.com/WillBarton888/dilithion/blob/main/TESTNET-LAUNCH.md) - Testnet guide
- [WHITEPAPER.md](https://github.com/WillBarton888/dilithion/blob/main/WHITEPAPER.md) - Technical specification
- [SECURITY.md](https://github.com/WillBarton888/dilithion/blob/main/docs/SECURITY.md) - Security documentation
- [CHANGELOG.md](https://github.com/WillBarton888/dilithion/blob/main/CHANGELOG.md) - Version history

## Disclaimer

⚠️ **EXPERIMENTAL SOFTWARE**
- Testnet coins have **NO VALUE**
- Use at your own risk
- No professional audit yet (planned before mainnet)
- AI-assisted development (full disclosure)
- Not financial advice

## Reporting Issues

Please report bugs at: https://github.com/WillBarton888/dilithion/issues

---

**Next Steps**: Join the testnet, mine blocks, report bugs, help us build the quantum-safe future! 🔐

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

---

## Step 2: After Publishing Release

### Configure Repository Settings

1. **Add Topics** - Go to repo home page, click gear icon next to "About":
   - `cryptocurrency`
   - `post-quantum`
   - `blockchain`
   - `quantum-resistant`
   - `dilithium`
   - `testnet`

2. **Enable Discussions**:
   - Go to Settings → General → Features
   - Check ✅ "Discussions"

3. **Create Discussion**:
   - Go to Discussions tab → New discussion
   - Category: Announcements
   - Title: "Dilithion Testnet Launch - Join Here!"
   - Content:
     ```markdown
     🚀 **Dilithion Testnet is Now Live!**

     Welcome to the Dilithion testnet! This is the official community hub for testnet participants.

     ## Quick Start
     📖 [TESTNET-LAUNCH.md](https://github.com/WillBarton888/dilithion/blob/main/TESTNET-LAUNCH.md)

     ## What We Need
     🐛 Bug hunters
     ⛏️ Miners (test stability)
     🌐 Seed node operators
     📝 Code reviewers

     ## Seed Node IPs
     Post your seed node IPs here to help the network!

     ## Questions?
     Ask here or open an issue!

     **Testnet coins have NO VALUE - for testing only**
     ```

---

## Step 3: Social Media (Use Templates)

All templates ready in: **TESTNET-ANNOUNCEMENT-TEMPLATES.md**

### Twitter/X
- Post the 5-tweet thread
- Pin to profile
- Hashtags: #PostQuantum #Cryptocurrency #Blockchain

### Reddit
- r/CryptoCurrency (main post)
- r/CryptoTechnology
- Use templates provided

### BitcoinTalk
- Create announcement thread
- Use email template format

---

## Quick Checklist

```
[ ] Create GitHub release (v1.0-testnet)
[ ] Add repository topics
[ ] Enable Discussions
[ ] Create discussion thread
[ ] Post Twitter announcement
[ ] Post Reddit announcement
[ ] Monitor responses
```

---

**You're ready to go live!** 🚀

Start with the GitHub release, then proceed with announcements at your own pace.
