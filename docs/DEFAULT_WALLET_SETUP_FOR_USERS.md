# Default Secure Wallet Setup for Dilithion Users & Miners

**Date:** 2025-11-10
**Version:** 1.0
**Purpose:** Secure-by-default wallet configuration for all Dilithion users

## Philosophy: Secure by Default, Easy for Everyone

### Core Principles:

1. **Security First**: Users protected even if they ignore warnings
2. **Guided Setup**: Step-by-step wizard on first launch
3. **No Choice Paralysis**: Good defaults, advanced options hidden
4. **Fail-Safe**: Mistakes should not lead to fund loss
5. **Education**: Teach security through the interface

---

## Recommended Default Configuration

### On First Launch: Mandatory Setup Wizard

```
┌──────────────────────────────────────────────────────────┐
│           WELCOME TO DILITHION WALLET                    │
│                                                          │
│  This wizard will create a secure wallet in 3 steps:    │
│                                                          │
│  1. Create HD Wallet (2 minutes)                        │
│  2. Secure Your Recovery Phrase (3 minutes)            │
│  3. Encrypt Wallet (1 minute)                           │
│                                                          │
│  Total time: ~5 minutes                                  │
│  Required: Paper and pen                                 │
│                                                          │
│  [Continue]  [Advanced Setup]  [Exit]                   │
└──────────────────────────────────────────────────────────┘
```

### Step 1: Automatic HD Wallet Creation

**What Happens:**
```
┌──────────────────────────────────────────────────────────┐
│  STEP 1: Create HD Wallet                               │
│                                                          │
│  ✓ Generating secure random seed...                     │
│  ✓ Creating 24-word recovery phrase...                  │
│  ✓ Deriving first addresses...                          │
│                                                          │
│  [Next: Secure Your Recovery Phrase]                    │
└──────────────────────────────────────────────────────────┘
```

**Default Settings (automatic):**
- HD wallet (always, no option to skip)
- BIP39 24-word mnemonic
- Standard derivation path (BIP44)
- No passphrase (keep it simple for most users)

### Step 2: Recovery Phrase Security (Interactive)

**Display with Education:**
```
┌──────────────────────────────────────────────────────────┐
│  STEP 2: Your Recovery Phrase                           │
│                                                          │
│  ⚠️  THIS IS THE ONLY WAY TO RECOVER YOUR FUNDS         │
│                                                          │
│  Your 24-word recovery phrase:                          │
│                                                          │
│  ╔══════════════════════════════════════════════════╗  │
│  ║  legal winner thank year wave sausage worth      ║  │
│  ║  useful legal winner thank year wave sausage     ║  │
│  ║  worth useful legal winner thank year wave       ║  │
│  ║  sausage worth useful legal winner               ║  │
│  ╚══════════════════════════════════════════════════╝  │
│                                                          │
│  REQUIRED: Write these words on paper RIGHT NOW          │
│                                                          │
│  ✓ DO: Write on paper, store in safe                   │
│  ✗ DON'T: Screenshot, email, or cloud storage          │
│                                                          │
│  To verify you wrote it down, type the 1st word:       │
│  [________________]                                      │
│                                                          │
│  [I've written it down]                                 │
└──────────────────────────────────────────────────────────┘
```

**Verification Required:**
- User must type first word correctly
- Optional: Type 12th and 24th word
- Cannot proceed until verified
- Option to print (with warnings)

### Step 3: Automatic Encryption

**Simple Passphrase Setup:**
```
┌──────────────────────────────────────────────────────────┐
│  STEP 3: Encrypt Your Wallet                            │
│                                                          │
│  Your wallet will be encrypted for security.             │
│                                                          │
│  Create a strong passphrase:                             │
│  • At least 12 characters                               │
│  • Mix letters, numbers, symbols                        │
│  • Something memorable but not guessable                │
│                                                          │
│  Passphrase: [____________________________]              │
│  Strength: ████████░░ Strong (80/100)                   │
│                                                          │
│  Confirm:    [____________________________]              │
│                                                          │
│  ⚠️  WARNING: If you forget this passphrase,            │
│     you can recover using your recovery phrase.          │
│                                                          │
│  [Encrypt Wallet]                                       │
└──────────────────────────────────────────────────────────┘
```

**Default Settings:**
- Encryption mandatory (cannot skip)
- Minimum 12 characters
- Real-time strength indicator
- Auto-lock after 5 minutes of inactivity
- Must confirm passphrase matches

### Step 4: Automatic Backup Creation

**Immediate Backup:**
```
┌──────────────────────────────────────────────────────────┐
│  STEP 4: Create Backup File                             │
│                                                          │
│  A backup file has been created:                         │
│                                                          │
│  📁 C:\Users\[user]\.dilithion\backups\                 │
│     wallet_backup_initial_20251110.txt                   │
│                                                          │
│  This file contains:                                     │
│  • Your recovery phrase                                 │
│  • Restoration instructions                             │
│  • Current wallet state                                  │
│                                                          │
│  ⚠️  SECURITY WARNING:                                  │
│  • Store this file on USB drive                         │
│  • Keep USB drive in safe                               │
│  • Make 2-3 copies                                      │
│  • NEVER email or cloud storage                         │
│                                                          │
│  [Open Backup Folder]  [Continue]                       │
└──────────────────────────────────────────────────────────┘
```

### Step 5: Setup Complete + First Address

**Welcome Screen:**
```
┌──────────────────────────────────────────────────────────┐
│  ✓ WALLET SETUP COMPLETE!                               │
│                                                          │
│  Your wallet is now secure and ready to use.             │
│                                                          │
│  Your first receive address:                             │
│  ╔══════════════════════════════════════════════════╗  │
│  ║  dil1qxyz123...abc456                            ║  │
│  ╚══════════════════════════════════════════════════╝  │
│                                                          │
│  [Copy Address]  [Show QR Code]                         │
│                                                          │
│  Security Checklist:                                     │
│  ✓ HD wallet created                                    │
│  ✓ Recovery phrase written on paper                    │
│  ✓ Wallet encrypted                                     │
│  ✓ Backup file created                                  │
│  ✓ Auto-backup enabled                                  │
│                                                          │
│  Next steps:                                             │
│  • Store recovery phrase in safe                        │
│  • Make 2-3 copies of backup file                       │
│  • Test wallet restoration (recommended)                │
│                                                          │
│  [Start Using Wallet]                                   │
└──────────────────────────────────────────────────────────┘
```

---

## Default Configuration Settings

### dilithion.conf (Secure Defaults)

```ini
# Dilithion Default Configuration
# Generated: 2025-11-10

# Wallet Settings
wallet=default
walletbroadcast=1

# HD Wallet (enabled by default)
usehd=1

# Encryption (mandatory)
walletencrypted=1
walletlocktimeout=300  # Auto-lock after 5 minutes

# Auto-Backup
autobackup=1
autobackupdir=~/.dilithion/backups
autobackupinterval=1440  # Daily backups (in minutes)

# Security
walletrequirepassphrase=1
disablewallet=0

# Network (safe defaults)
listen=0  # Don't accept incoming connections by default
upnp=0    # No UPnP (security)
maxconnections=8

# RPC (localhost only)
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Logging
debug=wallet
logips=0

# Mining Settings (for miners)
gen=0  # Mining disabled by default (enable manually)
genproclimit=1  # Use 1 core by default

# Transaction Settings
paytxfee=0.0001  # Default fee
mintxfee=0.00001
```

### Auto-Backup Configuration

**Default Backup Strategy:**
```
Backup Directory: ~/.dilithion/backups/
Backup Frequency: Daily (24 hours)
Backup Retention: 30 days
Backup Format: Human-readable text
File Permissions: 0600 (owner-only)

Backup Triggers:
- Daily automatic (24h interval)
- After wallet creation
- After receiving first transaction
- Before major updates
- On user request

Backup File Contents:
- Recovery phrase (encrypted in backup)
- Wallet state (addresses generated)
- Derivation info
- Restoration instructions
- Timestamp
```

---

## Mining-Specific Defaults

### For Solo Miners

**Default Configuration:**
```
┌──────────────────────────────────────────────────────────┐
│  MINING SETUP                                            │
│                                                          │
│  Your mining rewards will be sent to:                    │
│  dil1qxyz123...abc456                                    │
│                                                          │
│  Mining configuration:                                   │
│  • Solo mining enabled                                  │
│  • Using 1 CPU core                                     │
│  • Auto-withdraw: When balance > 100 DIL                │
│  • Withdraw to: [Your secure address]                   │
│                                                          │
│  Recommended: Use a separate address for mining          │
│  to track rewards separately.                            │
│                                                          │
│  [Generate Mining Address]  [Start Mining]              │
└──────────────────────────────────────────────────────────┘
```

**Security Features:**
- Separate mining address (tracks rewards)
- Auto-withdrawal to secure address
- Threshold-based transfers
- Daily mining reports

### For Pool Miners

**Default Configuration:**
```
┌──────────────────────────────────────────────────────────┐
│  POOL MINING SETUP                                       │
│                                                          │
│  Enter your pool's payout address:                       │
│  [dil1q_your_address_here_________________]              │
│                                                          │
│  Recommended Settings:                                   │
│  • Minimum payout: 10 DIL                               │
│  • Payment frequency: Daily                             │
│  • Separate pool wallet from personal wallet            │
│                                                          │
│  Pool earnings address:                                  │
│  dil1qpool123...mining456                                │
│                                                          │
│  Personal savings address:                               │
│  dil1qsecure789...savings012                             │
│                                                          │
│  [Save Configuration]                                    │
└──────────────────────────────────────────────────────────┘
```

---

## User Education: Built Into Interface

### Security Tips (Rotating Display)

**On Wallet Main Screen:**
```
┌──────────────────────────────────────────────────────────┐
│  💡 Security Tip of the Day:                            │
│                                                          │
│  Your recovery phrase is more important than your        │
│  passphrase. Your passphrase protects your wallet file, │
│  but your recovery phrase protects your funds forever.   │
│                                                          │
│  [Learn More]  [Next Tip]                               │
└──────────────────────────────────────────────────────────┘
```

**Daily Security Tips:**
1. "Never share your recovery phrase with anyone, including Dilithion support"
2. "Make multiple copies of your recovery phrase and store in different locations"
3. "Test your wallet restoration annually to ensure backups work"
4. "Use strong, unique passphrases - not your birthday or pet's name"
5. "Keep only small amounts in hot wallets, large amounts in cold storage"
6. "Enable auto-backup and check backup folder monthly"
7. "Update Dilithion wallet regularly for security patches"

### Interactive Security Checklist

**Accessible from Wallet Menu:**
```
┌──────────────────────────────────────────────────────────┐
│  SECURITY CHECKLIST                                      │
│                                                          │
│  Your security score: 85/100 (Very Good)                │
│                                                          │
│  ✓ Completed:                                           │
│    • HD wallet created                                  │
│    • Wallet encrypted                                   │
│    • Auto-backup enabled                                │
│    • Recovery phrase secured                            │
│                                                          │
│  ⚠  Recommended:                                         │
│    • Test wallet restoration                            │
│    • Create secondary backup                            │
│    • Review security settings                           │
│                                                          │
│  ℹ️  Tips to improve score:                             │
│    • Enable 2FA for wallet unlock (Advanced)            │
│    • Set up cold storage for large amounts              │
│                                                          │
│  [View Details]  [Dismiss]                              │
└──────────────────────────────────────────────────────────┘
```

---

## Default Warnings and Prompts

### When Sending Large Amounts

**Automatic Warning:**
```
┌──────────────────────────────────────────────────────────┐
│  ⚠️  LARGE TRANSACTION WARNING                          │
│                                                          │
│  You are about to send: 1,000 DIL                       │
│  Current value: ~$50,000 USD                             │
│                                                          │
│  This is a large transaction. Please verify:             │
│                                                          │
│  Recipient address:                                      │
│  dil1qxyz789...abc123                                    │
│                                                          │
│  ✓ I have verified the address is correct               │
│  ✓ I have verified the amount is correct                │
│  ✓ I understand this transaction is irreversible        │
│                                                          │
│  Type "CONFIRM" to proceed: [___________]                │
│                                                          │
│  [Cancel]  [Confirm Transaction]                         │
└──────────────────────────────────────────────────────────┘
```

**Threshold Defaults:**
- Warning for transactions > 100 DIL
- Confirmation required for > 500 DIL
- Delay (10 second countdown) for > 1,000 DIL

### Before Exporting Mnemonic

**Security Check:**
```
┌──────────────────────────────────────────────────────────┐
│  ⚠️  EXPORT RECOVERY PHRASE - SECURITY WARNING           │
│                                                          │
│  You are about to display your recovery phrase.          │
│                                                          │
│  Security checklist:                                     │
│  [ ] I am in a private location                         │
│  [ ] No one can see my screen                           │
│  [ ] No cameras or recording devices nearby             │
│  [ ] I have a legitimate reason to view this            │
│                                                          │
│  Common legitimate reasons:                              │
│  • Creating additional backup copies                    │
│  • Restoring wallet on new device                       │
│  • Verifying backup is correct                          │
│                                                          │
│  ⚠️  NEVER:                                              │
│  • Enter recovery phrase on websites                    │
│  • Share with anyone (including support)                │
│  • Type into untrusted applications                     │
│                                                          │
│  [Cancel]  [I Understand, Show Recovery Phrase]         │
└──────────────────────────────────────────────────────────┘
```

---

## Implementation: First-Run Wizard Code

### Integration with CWalletManager

**Modified Startup Flow:**

```cpp
// src/wallet/wallet_init.cpp

bool InitializeWallet() {
    // Check if this is first run
    if (!WalletExists()) {
        // Run mandatory setup wizard
        CWalletManager manager(nullptr);

        if (!manager.RunFirstTimeSetupWizard()) {
            // User cancelled setup
            LogPrintf("Wallet setup cancelled by user\n");
            return false;
        }

        // Wizard completed, wallet created
        LogPrintf("Wallet setup completed successfully\n");
    }

    // Load existing wallet
    CWallet* wallet = LoadWallet();

    // Verify wallet is encrypted
    if (!wallet->IsCrypted()) {
        // Should never happen with new wizard
        LogPrintf("WARNING: Wallet not encrypted!\n");
        // Force encryption
        ForceWalletEncryption(wallet);
    }

    // Enable auto-backup by default
    if (!AutoBackupEnabled()) {
        EnableAutoBackup(GetDefaultBackupDir(), 1440); // 24 hours
    }

    return true;
}
```

### CWalletManager Extension

**Add to wallet_manager.h:**

```cpp
class CWalletManager {
public:
    /**
     * Run first-time setup wizard
     * Returns true if setup completed, false if cancelled
     */
    bool RunFirstTimeSetupWizard();

    /**
     * Verify user wrote down mnemonic
     */
    bool VerifyMnemonicWritten(const std::string& mnemonic);

    /**
     * Display security education
     */
    void DisplaySecurityEducation();

    /**
     * Create initial backup with user prompts
     */
    bool CreateInitialBackup(const std::string& mnemonic);

    /**
     * Security score calculation
     */
    int CalculateSecurityScore() const;
};
```

---

## Default Directory Structure

```
~/.dilithion/
├── wallet.dat              # Encrypted wallet file
├── dilithion.conf         # Configuration (secure defaults)
├── backups/                # Auto-backup directory
│   ├── wallet_backup_initial_20251110.txt
│   ├── wallet_backup_auto_20251111.txt
│   ├── wallet_backup_auto_20251112.txt
│   └── ...
├── debug.log               # Logs (wallet operations)
└── peers.dat               # Network peers
```

**Permissions (Unix):**
```
wallet.dat: 0600 (owner read/write only)
backups/: 0700 (owner access only)
backup files: 0600 (owner read/write only)
```

---

## User Onboarding: Step-by-Step Guide

**Included with Wallet (PDF + Interactive):**

```markdown
# Getting Started with Dilithion Wallet

## Welcome! You're 5 minutes away from a secure wallet.

### What You'll Need:
- 5 minutes of time
- Paper and pen
- A safe place to store paper

### Step 1: Launch Wallet (30 seconds)
- Double-click Dilithion Wallet icon
- First-time setup wizard will start automatically

### Step 2: Create Wallet (30 seconds)
- Wallet generates automatically
- Wait for "Wallet created" message

### Step 3: Write Down Recovery Phrase (3 minutes)
- 24 words will be displayed
- Write each word on paper clearly
- Store paper in safe
- Verify by typing first word

### Step 4: Choose Passphrase (1 minute)
- Create strong passphrase (12+ characters)
- Confirm passphrase
- Wallet encrypts automatically

### Step 5: Done! (30 seconds)
- Backup file created automatically
- First address displayed
- Ready to receive Dilithion

## Important Security Rules:

1. ✓ DO keep recovery phrase on paper in safe
2. ✓ DO make multiple backup copies
3. ✓ DO test restoration annually
4. ✗ DON'T screenshot or email recovery phrase
5. ✗ DON'T share recovery phrase with anyone
6. ✗ DON'T store recovery phrase digitally

## Need Help?
- Help Menu → Security Guide
- Visit: docs.dilithion.org/security
- Community: forum.dilithion.org
```

---

## Miner-Specific Quick Start

**For Mining Pool Users:**

```markdown
# Dilithion Wallet for Miners - Quick Start

## Setup (2 minutes):

1. Install Dilithion Wallet
2. Complete 5-minute setup wizard
3. Get your receive address:
   - Wallet → Receive → Copy Address
4. Configure mining pool:
   - Paste address in pool settings
   - Set minimum payout (recommended: 10 DIL)

## Best Practices:

### Small-Scale Miner (<100 DIL/month):
- Use default wallet setup
- Enable auto-backup
- Withdraw to cold storage monthly

### Large-Scale Miner (>100 DIL/month):
- Use hot/cold wallet split
- Pool payouts → Hot wallet
- Auto-transfer to cold wallet weekly
- Keep max 10% in hot wallet

### Pool Configuration:
Mining Pool Address: [Your hot wallet address]
Minimum Payout: 10 DIL
Payment Frequency: Daily
Auto-Withdraw: When balance > 100 DIL → Cold wallet

## Security for Miners:

1. Separate mining wallet from personal wallet
2. Use auto-withdrawal to cold storage
3. Monitor balance daily
4. Encrypt wallet (mandatory)
5. Backup recovery phrase in safe
```

---

## Security Defaults Summary

### What's Automatic (No User Choice):
✅ HD wallet creation
✅ Wallet encryption
✅ Auto-backup enabled
✅ Secure file permissions
✅ Localhost-only RPC
✅ Auto-lock after 5 minutes
✅ Daily backups

### What Requires User Action:
📝 Write recovery phrase on paper
📝 Choose strong passphrase
📝 Store backup in safe
📝 Test restoration (recommended)

### What's Protected:
🔒 Recovery phrase never stored digitally
🔒 Wallet file encrypted at rest
🔒 Auto-lock prevents unauthorized access
🔒 Backups created automatically
🔒 Large transactions require confirmation
🔒 Security warnings on sensitive operations

---

## Conclusion

This default setup provides:

1. **Security**: Encrypted, backed up, guided setup
2. **Simplicity**: 5-minute wizard, good defaults
3. **Education**: Built-in tips, security checklist
4. **Safety**: Multiple layers of protection
5. **Recovery**: Always possible with recovery phrase

**Result**: Users are protected even if they make mistakes or ignore warnings. The system guides them toward security best practices without overwhelming them with choices.

**Recommendation**: Implement this as the default for Dilithion 1.0 launch.

---

**Document Version:** 1.0
**Target Audience:** All Dilithion Users (beginners to advanced)
**Implementation Priority:** High
**Estimated Dev Time:** 2-3 weeks for full implementation
