# Dilithion Wallet Integration Guide

**Version:** 1.0
**Last Updated:** October 27, 2025
**Target Audience:** Developers integrating with Dilithion wallet

---

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Wallet Initialization](#wallet-initialization)
4. [Creating Transactions](#creating-transactions)
5. [Sending Transactions](#sending-transactions)
6. [Balance Management](#balance-management)
7. [Error Handling](#error-handling)
8. [Security Best Practices](#security-best-practices)
9. [Advanced Topics](#advanced-topics)
10. [API Reference](#api-reference)

---

## Introduction

The Dilithion wallet provides a complete transaction management system using post-quantum CRYSTALS-Dilithium3 signatures. This guide explains how to integrate wallet functionality into your application.

### Key Features

- **Post-Quantum Security**: Dilithium3 signatures resistant to quantum attacks
- **UTXO Model**: Bitcoin-style unspent transaction output system
- **Automatic Coin Selection**: Greedy algorithm selects UTXOs automatically
- **Change Handling**: Automatic change output creation
- **Mempool Integration**: Direct transaction broadcasting
- **Thread-Safe**: Concurrent operations supported

### Prerequisites

- Understanding of UTXO model
- C++11 or later
- LevelDB for UTXO storage
- Dilithium library (included in depends/)

---

## Quick Start

### Minimal Example: Send Transaction

```cpp
#include <wallet/wallet.h>
#include <node/utxo_set.h>
#include <node/mempool.h>

// 1. Initialize wallet
CWallet wallet;
wallet.Load("wallet.dat");
wallet.Unlock("my_password", 0);  // If encrypted

// 2. Initialize UTXO set
CUTXOSet utxo_set;
utxo_set.Open(".dilithion/utxo");

// 3. Initialize mempool
CTxMemPool mempool;
mempool.SetHeight(current_blockchain_height);

// 4. Create recipient address
CAddress recipient_address;
recipient_address.SetString("D7NspzVjxpssktCxBd8RNFspqDFkCQWNbb");

// 5. Create transaction
CAmount amount = 50000000;  // 0.5 DLT
CAmount fee = CWallet::EstimateFee();
CTransactionRef tx;
std::string error;

if (!wallet.CreateTransaction(recipient_address, amount, fee,
                              utxo_set, current_height, tx, error)) {
    std::cerr << "Transaction creation failed: " << error << std::endl;
    return false;
}

// 6. Send transaction
if (!wallet.SendTransaction(tx, mempool, utxo_set, current_height, error)) {
    std::cerr << "Transaction broadcast failed: " << error << std::endl;
    return false;
}

std::cout << "Transaction sent! TxID: " << tx->GetHash().ToString() << std::endl;
```

---

## Wallet Initialization

### Creating a New Wallet

```cpp
#include <wallet/wallet.h>

CWallet wallet;

// Generate first key pair
if (!wallet.GenerateNewKey()) {
    std::cerr << "Failed to generate key" << std::endl;
    return false;
}

// Get receiving address
CAddress my_address = wallet.GetNewAddress();
std::cout << "Your address: " << my_address.ToString() << std::endl;

// Save wallet
wallet.SetWalletFile("~/.dilithion/wallet.dat");
if (!wallet.Save()) {
    std::cerr << "Failed to save wallet" << std::endl;
    return false;
}
```

### Loading an Existing Wallet

```cpp
CWallet wallet;

if (!wallet.Load("~/.dilithion/wallet.dat")) {
    std::cerr << "Failed to load wallet" << std::endl;
    return false;
}

// Check if encrypted
if (wallet.IsCrypted()) {
    // Wallet is encrypted, need to unlock
    if (!wallet.Unlock("my_password", 300)) {  // Unlock for 5 minutes
        std::cerr << "Wrong password or unlock failed" << std::endl;
        return false;
    }
}
```

### Encrypting a Wallet

```cpp
// Encrypt wallet with passphrase
if (!wallet.EncryptWallet("strong_password_here")) {
    std::cerr << "Encryption failed" << std::endl;
    return false;
}

// Wallet is now encrypted and unlocked
// Remember to lock when done with sensitive operations
wallet.Lock();
```

---

## Creating Transactions

### Basic Transaction Creation

```cpp
// Required components
CAddress recipient;
CAmount amount = 100000000;  // 1.0 DLT (100 million ions)
CAmount fee = CWallet::EstimateFee();  // 1000 ions (0.00001 DLT)
CUTXOSet& utxo_set;  // Global UTXO set reference
unsigned int current_height = blockchain_height;
CTransactionRef tx;
std::string error;

// Create transaction
bool success = wallet.CreateTransaction(
    recipient,
    amount,
    fee,
    utxo_set,
    current_height,
    tx,
    error
);

if (!success) {
    std::cerr << "Error: " << error << std::endl;
    return false;
}

// Transaction is now created and signed
std::cout << "Transaction ID: " << tx->GetHash().ToString() << std::endl;
std::cout << "Inputs: " << tx->vin.size() << std::endl;
std::cout << "Outputs: " << tx->vout.size() << std::endl;
```

### Transaction Creation Pipeline

The `CreateTransaction` method performs these steps automatically:

1. **Input Validation**
   - Checks recipient address is valid
   - Verifies amount > 0
   - Verifies fee ≥ 0
   - Checks for overflow

2. **Coin Selection**
   - Calls `SelectCoins` internally
   - Selects sufficient UTXOs to cover amount + fee
   - Returns error if insufficient balance

3. **Transaction Building**
   - Creates CTxIn for each selected UTXO
   - Creates CTxOut for recipient (amount)
   - Creates CTxOut for change (if any)

4. **Transaction Signing**
   - Signs each input with Dilithium3
   - Builds scriptSig for each input
   - Verifies wallet has keys for all inputs

5. **Validation**
   - Runs complete transaction validation
   - Checks signatures are valid
   - Verifies no double-spending

### Manual Coin Selection

```cpp
// Get all spendable UTXOs
std::vector<CWalletTx> unspent = wallet.ListUnspentOutputs(utxo_set, current_height);

std::cout << "Spendable outputs:" << std::endl;
for (const CWalletTx& wtx : unspent) {
    std::cout << "  " << wtx.txid.ToString() << ":" << wtx.vout
              << " = " << wtx.nValue << " ions" << std::endl;
}

// Manual coin selection
CAmount target = 50001000;  // amount + fee
std::vector<CWalletTx> selected;
CAmount total;
std::string error;

if (!wallet.SelectCoins(target, selected, total, utxo_set, current_height, error)) {
    std::cerr << "Insufficient funds: " << error << std::endl;
    return false;
}

std::cout << "Selected " << selected.size() << " coins totaling " << total << std::endl;
```

---

## Sending Transactions

### Broadcasting to Mempool

```cpp
CTransactionRef tx;  // Created transaction
CTxMemPool& mempool;  // Mempool reference
CUTXOSet& utxo_set;  // UTXO set reference
unsigned int current_height = blockchain_height;
std::string error;

// Send transaction
if (!wallet.SendTransaction(tx, mempool, utxo_set, current_height, error)) {
    std::cerr << "Broadcast failed: " << error << std::endl;

    // Check specific error
    if (error.find("double-spend") != std::string::npos) {
        // Handle double-spend attempt
    } else if (error.find("signature") != std::string::npos) {
        // Handle signature error
    }

    return false;
}

// Transaction accepted to mempool
std::cout << "Transaction " << tx->GetHash().ToString() << " accepted!" << std::endl;

// Check mempool
if (mempool.Exists(tx->GetHash())) {
    std::cout << "Confirmed in mempool" << std::endl;
}
```

### Transaction Lifecycle

```
1. CreateTransaction
   ↓
2. SendTransaction
   ↓
3. Mempool (validated, queued)
   ↓
4. Mining (included in block)
   ↓
5. Blockchain (confirmed)
   ↓
6. UTXO Set (outputs spendable)
```

---

## Balance Management

### Getting Wallet Balance

```cpp
CUTXOSet& utxo_set;
unsigned int current_height = blockchain_height;

// Get spendable balance (excludes immature coinbase)
CAmount balance = wallet.GetAvailableBalance(utxo_set, current_height);

std::cout << "Spendable balance: " << balance << " ions" << std::endl;
std::cout << "Spendable balance: " << (balance / COIN) << " DLT" << std::endl;

// Convert to human-readable
double dlt_balance = (double)balance / COIN;
std::cout << "Balance: " << std::fixed << std::setprecision(8) << dlt_balance << " DLT" << std::endl;
```

### Understanding Balance

**Total Balance vs Available Balance:**
- **Total**: All UTXOs owned by wallet
- **Available**: Mature UTXOs (coinbase with 100+ confirmations)

**Coinbase Maturity:**
```cpp
// Coinbase requires 100 confirmations
const unsigned int COINBASE_MATURITY = 100;

// Example:
// Block 150: Receive coinbase reward
// Block 250: Coinbase becomes spendable (150 + 100)
```

### Tracking Wallet UTXOs

```cpp
// Add received UTXO to wallet
uint256 txid = /* transaction id */;
uint32_t vout = /* output index */;
CAmount nValue = /* output value */;
CAddress address = wallet.GetNewAddress();
uint32_t nHeight = /* block height */;

if (!wallet.AddTxOut(txid, vout, nValue, address, nHeight)) {
    std::cerr << "Failed to add UTXO to wallet" << std::endl;
}

// Mark UTXO as spent
if (!wallet.MarkSpent(txid, vout)) {
    std::cerr << "Failed to mark UTXO as spent" << std::endl;
}

// List all unspent outputs
std::vector<CWalletTx> unspent = wallet.GetUnspentTxOuts();
for (const CWalletTx& wtx : unspent) {
    if (!wtx.fSpent) {
        std::cout << "UTXO: " << wtx.txid.ToString() << ":" << wtx.vout
                  << " = " << wtx.nValue << " ions" << std::endl;
    }
}
```

---

## Error Handling

### Common Errors and Solutions

#### 1. Insufficient Balance

```cpp
CTransactionRef tx;
std::string error;

if (!wallet.CreateTransaction(recipient, amount, fee, utxo_set, height, tx, error)) {
    if (error.find("Insufficient balance") != std::string::npos) {
        // Not enough funds
        CAmount balance = wallet.GetAvailableBalance(utxo_set, height);
        std::cerr << "Need " << (amount + fee) << " but only have " << balance << std::endl;

        // Suggest waiting for maturity
        std::cerr << "Some coinbase outputs may still be immature" << std::endl;
    }
}
```

#### 2. Invalid Recipient Address

```cpp
CAddress recipient;
if (!recipient.SetString(user_input_address)) {
    std::cerr << "Invalid address format" << std::endl;
    std::cerr << "Example valid address: D7NspzVjxpssktCxBd8RNFspqDFkCQWNbb" << std::endl;
    return false;
}
```

#### 3. Wallet Locked

```cpp
if (!wallet.CreateTransaction(recipient, amount, fee, utxo_set, height, tx, error)) {
    if (error.find("locked") != std::string::npos || wallet.IsLocked()) {
        // Wallet is encrypted and locked
        std::cout << "Please unlock wallet with password:" << std::endl;

        std::string password;
        std::cin >> password;

        if (!wallet.Unlock(password, 300)) {  // 5 minutes
            std::cerr << "Wrong password" << std::endl;
            return false;
        }

        // Retry transaction creation
    }
}
```

#### 4. Signature Failure

```cpp
if (error.find("sign") != std::string::npos) {
    // Signing failed - wallet may not have the required keys
    std::cerr << "Transaction signing failed" << std::endl;
    std::cerr << "Wallet may not own the UTXOs being spent" << std::endl;

    // Check wallet addresses
    std::vector<CAddress> addresses = wallet.GetAddresses();
    std::cout << "Wallet addresses:" << std::endl;
    for (const CAddress& addr : addresses) {
        std::cout << "  " << addr.ToString() << std::endl;
    }
}
```

### Error Handling Pattern

```cpp
// Recommended error handling pattern
CTransactionRef tx;
std::string error;

try {
    if (!wallet.CreateTransaction(recipient, amount, fee, utxo_set, height, tx, error)) {
        // Log error for debugging
        LogPrintf("Transaction creation failed: %s\n", error);

        // User-friendly error message
        if (error.find("Insufficient") != std::string::npos) {
            throw std::runtime_error("Not enough funds in wallet");
        } else if (error.find("locked") != std::string::npos) {
            throw std::runtime_error("Wallet is locked - please unlock first");
        } else {
            throw std::runtime_error("Transaction creation failed: " + error);
        }
    }

    // Success path
    LogPrintf("Transaction created: %s\n", tx->GetHash().ToString());

} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return false;
}
```

---

## Security Best Practices

### 1. Wallet Encryption

```cpp
// Always encrypt wallets containing private keys
if (!wallet.IsCrypted()) {
    std::cout << "WARNING: Wallet is not encrypted!" << std::endl;
    std::cout << "Encrypt now? (y/n): ";

    char response;
    std::cin >> response;

    if (response == 'y') {
        std::string password;
        std::cout << "Enter encryption password: ";
        std::cin >> password;

        if (!wallet.EncryptWallet(password)) {
            std::cerr << "Encryption failed" << std::endl;
        } else {
            std::cout << "Wallet encrypted successfully" << std::endl;
        }
    }
}
```

### 2. Secure Password Handling

```cpp
// DON'T store passwords in plain text
// DON'T log passwords
// DO use secure input methods

#include <termios.h>  // For password input without echo

std::string GetPasswordSecure() {
    std::string password;

    // Disable echo
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Get password
    std::cout << "Password: ";
    std::getline(std::cin, password);
    std::cout << std::endl;

    // Restore echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return password;
}
```

### 3. Unlock Timeout

```cpp
// Unlock wallet with timeout (recommended)
int timeout_seconds = 300;  // 5 minutes

if (!wallet.Unlock(password, timeout_seconds)) {
    std::cerr << "Unlock failed" << std::endl;
    return false;
}

std::cout << "Wallet unlocked for " << timeout_seconds << " seconds" << std::endl;

// Perform sensitive operations
CreateAndSendTransaction();

// Lock manually after operations
wallet.Lock();
std::cout << "Wallet locked" << std::endl;
```

### 4. Backup Strategy

```cpp
// Regular backups are critical
bool BackupWallet(const std::string& backup_path) {
    CWallet wallet;

    if (!wallet.Load(WALLET_FILE)) {
        std::cerr << "Failed to load wallet" << std::endl;
        return false;
    }

    // Save to backup location
    if (!wallet.Save(backup_path)) {
        std::cerr << "Backup failed" << std::endl;
        return false;
    }

    std::cout << "Wallet backed up to: " << backup_path << std::endl;
    return true;
}

// Schedule regular backups
void ScheduleBackups() {
    // Backup every day
    std::string timestamp = GetCurrentTimestamp();
    std::string backup_file = "wallet_backup_" + timestamp + ".dat";
    BackupWallet(backup_file);
}
```

### 5. Transaction Verification

```cpp
// Always verify transaction details before sending
void DisplayTransactionDetails(const CTransactionRef& tx) {
    std::cout << "\nTransaction Details:" << std::endl;
    std::cout << "  TX ID: " << tx->GetHash().ToString() << std::endl;
    std::cout << "  Inputs: " << tx->vin.size() << std::endl;
    std::cout << "  Outputs: " << tx->vout.size() << std::endl;

    CAmount total_out = 0;
    for (size_t i = 0; i < tx->vout.size(); i++) {
        total_out += tx->vout[i].nValue;
        std::cout << "    Output " << i << ": "
                  << tx->vout[i].nValue << " ions" << std::endl;
    }

    std::cout << "  Total: " << total_out << " ions" << std::endl;
}

// Get user confirmation
bool ConfirmTransaction(const CTransactionRef& tx) {
    DisplayTransactionDetails(tx);

    std::cout << "\nConfirm this transaction? (yes/no): ";
    std::string response;
    std::cin >> response;

    return (response == "yes" || response == "y");
}

// Usage
if (ConfirmTransaction(tx)) {
    wallet.SendTransaction(tx, mempool, utxo_set, height, error);
} else {
    std::cout << "Transaction cancelled" << std::endl;
}
```

---

## Advanced Topics

### Custom Coin Selection

```cpp
// Implement custom coin selection strategy
class CustomCoinSelector {
public:
    bool SelectCoinsCustom(
        const std::vector<CWalletTx>& available_coins,
        CAmount target_value,
        std::vector<CWalletTx>& selected,
        CAmount& total_value
    ) {
        // Example: Privacy-focused selection (mix sizes)
        // Sort by value
        std::vector<CWalletTx> sorted = available_coins;
        std::sort(sorted.begin(), sorted.end(),
                  [](const CWalletTx& a, const CWalletTx& b) {
                      return a.nValue < b.nValue;
                  });

        // Select mix of small and large UTXOs
        total_value = 0;
        for (size_t i = 0; i < sorted.size() && total_value < target_value; i += 2) {
            selected.push_back(sorted[i]);
            total_value += sorted[i].nValue;
        }

        return total_value >= target_value;
    }
};
```

### Fee Calculation

```cpp
// Current: Fixed fee
CAmount current_fee = CWallet::DEFAULT_TRANSACTION_FEE;  // 1000 ions

// Future: Dynamic fee calculation
CAmount CalculateDynamicFee(const CTransaction& tx, const CTxMemPool& mempool) {
    // Base fee per byte
    CAmount fee_per_byte = 1;  // 1 ion per byte

    // Get transaction size
    size_t tx_size = tx.GetSerializedSize();

    // Calculate base fee
    CAmount base_fee = tx_size * fee_per_byte;

    // Adjust for mempool congestion
    size_t mempool_size = mempool.Size();
    double congestion_multiplier = 1.0;

    if (mempool_size > 1000) {
        congestion_multiplier = 2.0;  // Double fee when congested
    }

    return base_fee * congestion_multiplier;
}
```

### Transaction History

```cpp
// Track transaction history
class TransactionHistory {
private:
    std::vector<CTransactionRef> sent_transactions;
    std::vector<CTransactionRef> received_transactions;

public:
    void AddSent(const CTransactionRef& tx) {
        sent_transactions.push_back(tx);
    }

    void AddReceived(const CTransactionRef& tx) {
        received_transactions.push_back(tx);
    }

    void Display() const {
        std::cout << "Sent Transactions:" << std::endl;
        for (const auto& tx : sent_transactions) {
            std::cout << "  " << tx->GetHash().ToString()
                      << " - " << tx->GetValueOut() << " ions" << std::endl;
        }

        std::cout << "\nReceived Transactions:" << std::endl;
        for (const auto& tx : received_transactions) {
            std::cout << "  " << tx->GetHash().ToString()
                      << " - " << tx->GetValueOut() << " ions" << std::endl;
        }
    }
};
```

---

## API Reference

### CWallet Methods

#### Constructor/Destructor
```cpp
CWallet();
~CWallet();
```

#### Key Management
```cpp
bool GenerateNewKey();
CAddress GetNewAddress();
std::vector<CAddress> GetAddresses() const;
bool HasKey(const CAddress& address) const;
bool GetKey(const CAddress& address, CKey& keyOut) const;
```

#### UTXO Management
```cpp
bool ScanUTXOs(CUTXOSet& global_utxo_set);
CAmount GetAvailableBalance(CUTXOSet& utxo_set, unsigned int current_height) const;
std::vector<CWalletTx> ListUnspentOutputs(CUTXOSet& utxo_set, unsigned int current_height) const;
bool AddTxOut(const uint256& txid, uint32_t vout, int64_t nValue, const CAddress& address, uint32_t nHeight);
bool MarkSpent(const uint256& txid, uint32_t vout);
std::vector<CWalletTx> GetUnspentTxOuts() const;
```

#### Transaction Creation
```cpp
bool CreateTransaction(
    const CAddress& recipient_address,
    CAmount amount,
    CAmount fee,
    CUTXOSet& utxo_set,
    unsigned int current_height,
    CTransactionRef& tx_out,
    std::string& error
);

bool SelectCoins(
    CAmount target_value,
    std::vector<CWalletTx>& selected_coins,
    CAmount& total_value,
    CUTXOSet& utxo_set,
    unsigned int current_height,
    std::string& error
) const;

bool SignTransaction(CTransaction& tx, CUTXOSet& utxo_set, std::string& error);
```

#### Transaction Broadcasting
```cpp
bool SendTransaction(
    const CTransactionRef& tx,
    CTxMemPool& mempool,
    CUTXOSet& utxo_set,
    unsigned int current_height,
    std::string& error
);

static CAmount EstimateFee();  // Returns DEFAULT_TRANSACTION_FEE (1000 ions)
static const CAmount DEFAULT_TRANSACTION_FEE = 1000;
```

#### Wallet Encryption
```cpp
bool EncryptWallet(const std::string& passphrase);
bool Unlock(const std::string& passphrase, int64_t timeout = 0);
bool Lock();
bool IsLocked() const;
bool IsCrypted() const;
bool ChangePassphrase(const std::string& passphraseOld, const std::string& passphraseNew);
```

#### Persistence
```cpp
bool Load(const std::string& filename);
bool Save(const std::string& filename = "") const;
void SetWalletFile(const std::string& filename);
std::string GetWalletFile() const;
void SetAutoSave(bool enabled);
void Clear();
```

#### Helper Methods
```cpp
std::vector<uint8_t> GetPubKeyHash() const;
std::vector<uint8_t> GetPublicKey() const;
static std::vector<uint8_t> GetPubKeyHashFromAddress(const CAddress& address);
size_t GetKeyPoolSize() const;
```

---

## Constants

```cpp
// Amount type (int64_t, in ions)
static const CAmount COIN = 100000000;  // 1 DLT = 100 million ions
static const CAmount CENT = 1000000;    // 0.01 DLT

// Transaction fee
static const CAmount DEFAULT_TRANSACTION_FEE = 1000;  // 0.00001 DLT

// Coinbase maturity
static const unsigned int COINBASE_MATURITY = 100;  // 100 confirmations

// Dilithium key sizes
static const size_t DILITHIUM_PUBLICKEY_SIZE = 1952;
static const size_t DILITHIUM_SECRETKEY_SIZE = 4032;
static const size_t DILITHIUM_SIGNATURE_SIZE = 3309;
```

---

## Support

For additional help:
- GitHub: https://github.com/dilithion/dilithion
- Documentation: https://docs.dilithion.org
- Discord: https://discord.gg/dilithion

---

**Last Updated:** October 27, 2025
**Version:** 1.0 (Phase 5.2)
**License:** MIT
