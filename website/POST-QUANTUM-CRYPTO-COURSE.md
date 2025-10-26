# Post-Quantum Cryptocurrency: A Beginner's Guide to Dilithion

**Welcome to the Dilithion Learning Center**

This comprehensive course will teach you everything you need to know about post-quantum cryptography, blockchain technology, and how Dilithion protects your assets from quantum computers.

**Course Duration:** 7 modules, ~30 minutes each
**Skill Level:** Beginner-friendly (no prior crypto knowledge required)
**Certificate:** Share your completion on social media!

---

## Table of Contents

1. [The Quantum Threat](#module-1-the-quantum-threat)
2. [How Post-Quantum Cryptography Works](#module-2-how-post-quantum-cryptography-works)
3. [Understanding Blockchain Basics](#module-3-understanding-blockchain-basics)
4. [Dilithion's Architecture](#module-4-dilithions-architecture)
5. [Mining & Proof-of-Work](#module-5-mining--proof-of-work)
6. [Wallet Security & Best Practices](#module-6-wallet-security--best-practices)
7. [The Future of Quantum-Safe Crypto](#module-7-the-future-of-quantum-safe-crypto)

---

# Module 1: The Quantum Threat

**Duration:** 30 minutes
**What You'll Learn:** Why current cryptocurrencies are vulnerable and when quantum computers will break them

---

## 1.1 What is a Quantum Computer?

### Classical Computers (What We Use Today)

Your laptop, phone, and every computer since the 1940s works with **bits**:
- A bit is either **0** or **1**
- Like a light switch: ON or OFF
- To break encryption, must try many combinations sequentially

### Quantum Computers (The Future)

Quantum computers use **qubits**:
- Can be 0, 1, or **both simultaneously** (superposition)
- Can process many calculations in parallel
- Exponentially faster for certain mathematical problems

**Think of it like this:**
```
Classical computer searching a maze:
- Tries one path at a time
- If wrong, backs up and tries another path
- Takes a LONG time for complex mazes

Quantum computer searching a maze:
- Tries ALL paths simultaneously
- Finds the solution instantly (for certain types of problems)
```

---

## 1.2 How Quantum Computers Break Current Crypto

### The Algorithm That Changes Everything: Shor's Algorithm (1994)

**Peter Shor** discovered that quantum computers can solve two critical problems efficiently:

1. **Factoring large numbers** (RSA encryption relies on this being hard)
2. **Discrete logarithm problem** (ECDSA signatures rely on this being hard)

### What This Means for Bitcoin, Ethereum, and Most Cryptocurrencies

**Current Situation:**
```
Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
├─ Public Key: Visible when you spend coins
├─ Private Key: Secret (controls your money)
└─ Security: Deriving private key from public key is impossible... today

Classical Computer:
- Would take 2^128 operations (billions of years)
- Your Bitcoin is safe

Quantum Computer with Shor's Algorithm:
- Could derive private key in HOURS or DAYS
- Your Bitcoin could be stolen
```

**Real-world timeline:**
- **2025 (Now):** Quantum computers exist but are too small (~1,000 qubits)
- **2030-2035:** Experts predict "cryptographically relevant" quantum computers (~4,000+ logical qubits)
- **When they arrive:** Bitcoin, Ethereum, and 95%+ of cryptocurrencies become vulnerable

---

## 1.3 Which Cryptocurrencies Are Vulnerable?

### ❌ Vulnerable to Quantum Attacks

**Uses ECDSA or RSA signatures:**
- Bitcoin (BTC)
- Ethereum (ETH)
- Litecoin (LTC)
- Ripple (XRP)
- Cardano (ADA)
- Polkadot (DOT)
- Solana (SOL)
- **95%+ of all cryptocurrencies**

**Why?** All use Elliptic Curve Digital Signature Algorithm (ECDSA), which Shor's Algorithm breaks.

### ✅ Quantum-Resistant (Post-Quantum Cryptocurrencies)

**Uses lattice-based or other PQ cryptography:**
- **Dilithion** (CRYSTALS-Dilithium3 + SHA-3)
- Quantum Resistant Ledger (QRL) - XMSS signatures
- *Very few others exist*

---

## 1.4 The "Store Now, Decrypt Later" Attack

### Why We Need to Act NOW (Even Before Quantum Computers Exist)

**The Threat:**
```
1. Adversary (government, hacker) records ALL blockchain transactions TODAY
2. Stores encrypted data for 5-10 years
3. When quantum computers arrive in 2030-2035...
4. Decrypts historical data and steals old private keys
5. Empties wallets that were "secure" years ago
```

**This is already happening:**
- NSA and intelligence agencies record encrypted internet traffic
- China announced quantum computing initiatives
- Once quantum computers exist, historical Bitcoin transactions become vulnerable

**Dilithion's solution:**
- Quantum-safe from genesis block (January 1, 2026)
- No historical vulnerability
- Future-proof from day one

---

## 1.5 Quiz: Test Your Knowledge

**Question 1:** What makes quantum computers different from classical computers?

a) They're faster at everything
b) They use qubits that can be 0, 1, or both simultaneously
c) They run on quantum energy
d) They're more expensive

<details>
<summary>Answer</summary>
**b) They use qubits that can be 0, 1, or both simultaneously**

Quantum computers aren't faster at everything - they're exponentially faster at specific mathematical problems like factoring and discrete logarithm. This superposition property is what makes them powerful.
</details>

---

**Question 2:** What algorithm allows quantum computers to break ECDSA signatures?

a) Grover's Algorithm
b) Shor's Algorithm
c) Bitcoin's Algorithm
d) RSA Algorithm

<details>
<summary>Answer</summary>
**b) Shor's Algorithm**

Shor's Algorithm (1994) can efficiently solve the discrete logarithm problem on quantum computers, breaking ECDSA. Grover's Algorithm only provides quadratic speedup (still safe for hashing).
</details>

---

**Question 3:** When do experts predict quantum computers will threaten cryptocurrencies?

a) 2025 (now)
b) 2030-2035
c) 2050+
d) Never

<details>
<summary>Answer</summary>
**b) 2030-2035**

Most cryptography experts predict cryptographically-relevant quantum computers (4,000+ logical qubits) will exist between 2030-2035. Some estimates are more conservative (2040s), but prudent to prepare now.
</details>

---

**Question 4:** Why should we worry about quantum computers NOW if they don't exist yet?

a) We shouldn't worry
b) "Store now, decrypt later" attacks are already happening
c) Quantum computers are more expensive
d) Bitcoin will automatically upgrade

<details>
<summary>Answer</summary>
**b) "Store now, decrypt later" attacks are already happening**

Adversaries can record encrypted blockchain data TODAY and decrypt it when quantum computers arrive in 5-10 years. Historical transactions would be compromised. This is why Dilithion launches quantum-safe from genesis.
</details>

---

## Module 1 Complete! 🎉

**You've learned:**
✅ What quantum computers are and how they differ from classical computers
✅ Why Shor's Algorithm breaks current cryptocurrency signatures
✅ Which cryptocurrencies are vulnerable (Bitcoin, Ethereum, 95%+ of all crypto)
✅ The "store now, decrypt later" threat
✅ Why we need post-quantum crypto NOW, not later

**Next Module:** How Post-Quantum Cryptography Works

---

# Module 2: How Post-Quantum Cryptography Works

**Duration:** 30 minutes
**What You'll Learn:** The mathematics protecting Dilithion from quantum attacks

---

## 2.1 The Two Types of Cryptography in Cryptocurrencies

### 1. Digital Signatures (Proving Ownership)

**What they do:**
- Prove you own your cryptocurrency
- Sign transactions to authorize spending
- Anyone can verify the signature is legitimate

**Classical crypto (ECDSA):**
- Based on elliptic curve math
- ❌ Vulnerable to quantum computers

**Post-quantum crypto (Dilithium):**
- Based on lattice math
- ✅ Resistant to quantum computers

---

### 2. Hash Functions (Data Integrity)

**What they do:**
- Create unique "fingerprints" of data
- Used for addresses, block IDs, proof-of-work
- One-way function (can't reverse)

**Classical crypto (SHA-256):**
- Used by Bitcoin
- ✅ Mostly safe from quantum (Grover's algorithm only halves security)

**Post-quantum crypto (SHA-3):**
- Used by Dilithion
- ✅ Same quantum resistance, newer design (NIST FIPS 202)

---

## 2.2 CRYSTALS-Dilithium: The Quantum-Safe Signature Scheme

### What is CRYSTALS-Dilithium?

**Official NIST Post-Quantum Cryptography Standard**
- Selected by NIST in 2022 after 6-year competition
- Based on **Module Learning With Errors (Module-LWE)**
- **FIPS 204** standard (officially approved by US government)
- Three security levels: Dilithium2, **Dilithium3**, Dilithium5

**Dilithion uses Dilithium3:**
- Security Level 3 (equivalent to AES-192 classical security)
- ~128-bit quantum security
- Balanced performance and security

---

### How Lattice Cryptography Works (Simplified)

**Imagine a 3D lattice (grid of points in space):**

```
Classical crypto (ECDSA):
Problem: Find a secret number on a curve
Quantum computer: Can solve easily with Shor's Algorithm

Lattice crypto (Dilithium):
Problem: Find the shortest vector in a high-dimensional lattice
Quantum computer: No efficient algorithm exists (problem remains hard!)
```

**The Security Assumption:**
Finding short vectors in high-dimensional lattices is hard, even for quantum computers.

**Has this been proven?**
- No mathematical proof (same as ECDSA)
- But: 30+ years of research, no quantum algorithm found
- NIST extensively analyzed and standardized it

---

### Key Sizes: The Tradeoff for Quantum Resistance

| Component | ECDSA (Bitcoin) | Dilithium3 (Dilithion) | Ratio |
|-----------|----------------|----------------------|-------|
| Public Key | 33 bytes | 1,952 bytes | 59x larger |
| Private Key | 32 bytes | 4,032 bytes | 126x larger |
| Signature | 72 bytes | 3,309 bytes | 46x larger |

**Why so large?**
- Lattice problems require more data (matrices, polynomials)
- ECDSA works with small numbers on elliptic curves
- This is the price of quantum resistance

**Does this matter?**
- Storage: Yes, blockchain grows faster
- Speed: No! Signing/verification is still milliseconds
- Security: Massive improvement (quantum-safe)

---

## 2.3 SHA-3: Quantum-Resistant Hashing

### Why Dilithion Uses SHA-3 Instead of SHA-256

**SHA-256 (Bitcoin):**
- Quantum security: ~128 bits (Grover's algorithm halves it from 256)
- Still secure! But older design (2001)

**SHA-3 (Keccak):**
- Quantum security: ~128 bits (same as SHA-256)
- Newer design (2015), different internal structure
- NIST FIPS 202 standard
- Used in Dilithium library (compatibility)

**Key Point:** Both are quantum-resistant for hashing. SHA-3 is more modern and aligns with post-quantum standards.

---

### What SHA-3 is Used For in Dilithion

1. **Block Hashing**
   - Creates unique ID for each block
   - Links blocks together in chain

2. **Transaction Hashing**
   - Creates transaction IDs (TXIDs)
   - What gets signed by Dilithium signatures

3. **Address Generation**
   - Hash public key → Create address
   - Double-hashing for extra security

4. **Proof-of-Work**
   - RandomX internally uses hashing
   - Mining difficulty based on hash values

---

## 2.4 The Complete Dilithion Cryptographic Stack

```
┌─────────────────────────────────────┐
│   DILITHION QUANTUM-SAFE STACK      │
├─────────────────────────────────────┤
│ Signatures: CRYSTALS-Dilithium3     │ ← Quantum-resistant (lattice)
│             NIST FIPS 204           │
├─────────────────────────────────────┤
│ Hashing:    SHA-3 (Keccak-256)      │ ← Quantum-resistant (Grover-safe)
│             NIST FIPS 202           │
├─────────────────────────────────────┤
│ Mining:     RandomX (CPU PoW)       │ ← ASIC-resistant, quantum-neutral
│             Memory-hard algorithm   │
└─────────────────────────────────────┘
```

**Every component is either:**
- ✅ Quantum-resistant (Dilithium, SHA-3)
- ⚪ Quantum-neutral (RandomX mining - quantum doesn't help)

---

## 2.5 NIST Post-Quantum Cryptography Competition

### The 6-Year Process (2016-2022)

**Round 1 (2017):** 69 candidate algorithms submitted
**Round 2 (2019):** 26 candidates advanced
**Round 3 (2020):** 7 finalists + 8 alternates
**Winners (2022):** 4 algorithms standardized

### The Winners

1. **CRYSTALS-Dilithium** (Digital Signatures) ← **Dilithion uses this!**
2. **CRYSTALS-Kyber** (Key Encapsulation)
3. **SPHINCS+** (Stateless Hash-Based Signatures)
4. **FALCON** (Lattice-Based Signatures)

**Why Dilithion chose Dilithium:**
- Most mature lattice-based signature scheme
- Best performance/security balance
- Widely studied and vetted
- Name similarity (happy coincidence!)

---

## 2.6 Quiz: Test Your Knowledge

**Question 1:** What mathematical problem is CRYSTALS-Dilithium based on?

a) Elliptic Curve Discrete Logarithm
b) RSA Factoring
c) Module Learning With Errors (Lattice problem)
d) SHA-256 Hashing

<details>
<summary>Answer</summary>
**c) Module Learning With Errors (Lattice problem)**

Dilithium's security is based on finding short vectors in high-dimensional lattices, a problem that remains hard even for quantum computers.
</details>

---

**Question 2:** Why are Dilithium signatures so much larger than ECDSA signatures?

a) They're inefficient
b) Lattice problems require more data (matrices/polynomials)
c) It's a mistake in the design
d) Quantum resistance requires redundant data

<details>
<summary>Answer</summary>
**b) Lattice problems require more data (matrices/polynomials)**

This is the fundamental tradeoff. ECDSA works with compact elliptic curve points, while lattice crypto needs larger structures. The security benefit (quantum resistance) is worth the size increase.
</details>

---

**Question 3:** How does SHA-3 compare to SHA-256 against quantum attacks?

a) SHA-3 is quantum-resistant, SHA-256 is not
b) Both provide similar quantum resistance (~128 bits)
c) SHA-256 is better
d) Neither is quantum-resistant

<details>
<summary>Answer</summary>
**b) Both provide similar quantum resistance (~128 bits)**

Grover's algorithm (best quantum attack on hash functions) only provides quadratic speedup, reducing 256-bit security to 128-bit. Both SHA-256 and SHA-3-256 remain secure. SHA-3 is newer and aligns better with post-quantum standards.
</details>

---

**Question 4:** When did NIST officially standardize CRYSTALS-Dilithium?

a) 2015
b) 2018
c) 2022
d) 2025

<details>
<summary>Answer</summary>
**c) 2022**

After a 6-year competition starting in 2016, NIST announced Dilithium as one of four winners in 2022. It was officially published as FIPS 204 standard.
</details>

---

## Module 2 Complete! 🎉

**You've learned:**
✅ The difference between signatures and hashing in crypto
✅ How CRYSTALS-Dilithium uses lattice math to resist quantum attacks
✅ Why Dilithium keys are larger (the tradeoff for quantum safety)
✅ How SHA-3 provides quantum-resistant hashing
✅ The complete Dilithion cryptographic stack
✅ How NIST vetted and standardized Dilithium over 6 years

**Next Module:** Understanding Blockchain Basics

---

# Module 3: Understanding Blockchain Basics

**Duration:** 30 minutes
**What You'll Learn:** How blockchains work, what makes them secure, and how Dilithion implements them

---

## 3.1 What is a Blockchain?

### The Simple Explanation

**A blockchain is a digital ledger (record book) that:**
- Records all transactions publicly
- Cannot be altered once written (immutable)
- No central authority controls it (decentralized)
- Everyone has a copy and agrees on the contents (consensus)

**Think of it like a public notebook:**
```
Page 1 (Block 1):
├─ Alice sends 10 coins to Bob
├─ Charlie sends 5 coins to Dave
└─ Hash: 0x1a2b3c... (fingerprint of this page)

Page 2 (Block 2):
├─ References Page 1's hash (0x1a2b3c...)
├─ Bob sends 5 coins to Eve
├─ Dave sends 2 coins to Frank
└─ Hash: 0x4d5e6f... (fingerprint of this page)

Each page references the previous page's hash.
If you change Page 1, the hash changes, breaking the chain.
```

---

## 3.2 Key Components of a Blockchain

### 1. Blocks

**Each block contains:**
```
Block Header:
├─ Version: Protocol version
├─ Previous Block Hash: Links to parent block
├─ Merkle Root: Hash of all transactions
├─ Timestamp: When block was created
├─ Difficulty: How hard it was to mine
└─ Nonce: Random number for mining

Block Body:
└─ Transactions: List of all transactions in this block
```

**In Dilithion:**
- Block time: 2 minutes (Bitcoin: 10 minutes)
- Max block size: Limited by signature size
- Hash function: SHA-3-256 (quantum-resistant!)

---

### 2. Transactions

**Standard transaction structure:**
```
Transaction:
├─ Inputs: Where coins come from
│   ├─ Previous transaction hash
│   ├─ Output index (which coin)
│   └─ Signature (proves you own it) ← Dilithium signature!
├─ Outputs: Where coins go to
│   ├─ Amount (how many coins)
│   └─ Public key hash (recipient's address)
└─ Fee: Reward for miner
```

**Example:**
```
Alice has 10 DIL (from a previous transaction)
She wants to send 7 DIL to Bob

Transaction:
├─ Input: Previous TX where Alice received 10 DIL
│   └─ Dilithium signature proving Alice owns it
├─ Output 1: 7 DIL to Bob's address
├─ Output 2: 2.9995 DIL to Alice (change)
└─ Fee: 0.0005 DIL to miner
```

---

### 3. UTXOs (Unspent Transaction Outputs)

**How Dilithion tracks coin ownership:**

**Not like a bank account:**
```
❌ Bank model:
Alice's account: 10 DIL
Bob's account: 5 DIL
(Just a balance in a database)
```

**UTXO model (what Dilithion uses):**
```
✅ UTXO model:
├─ Output #1: 10 DIL locked to Alice's public key (unspent)
├─ Output #2: 5 DIL locked to Bob's public key (unspent)
└─ Output #3: 3 DIL locked to Charlie's public key (spent)

Your "balance" = sum of all unspent outputs locked to your keys
```

**Why UTXO?**
- Better privacy (different addresses per transaction)
- Easier to verify (no account state to track)
- Prevents double-spending
- Bitcoin-style proven model

---

## 3.3 How Transactions Are Verified

### Step-by-Step Transaction Verification

**When a node receives a transaction:**

1. **Check structure**
   - Is transaction properly formatted?
   - Are all required fields present?

2. **Verify inputs exist**
   - Do the referenced outputs exist on the blockchain?
   - Are they unspent (not already spent)?

3. **Verify signatures** ← **Dilithium signature verification**
   ```cpp
   For each input:
     Extract public key from previous output
     Verify Dilithium signature matches
     If signature invalid → reject transaction
   ```

4. **Check amounts**
   - Sum of outputs ≤ Sum of inputs?
   - Fee = Inputs - Outputs (must be ≥ minimum)
   - No negative values?
   - No integer overflow?

5. **Check against consensus rules**
   - Coinbase (mining reward) only in first transaction?
   - Block reward correct for height?
   - Difficulty valid?

**If ALL checks pass → Transaction is valid**

---

## 3.4 The Mempool: Waiting Room for Transactions

### What is the Mempool?

**Memory Pool (Mempool):**
- Temporary storage for unconfirmed transactions
- Each node maintains its own mempool
- Miners select transactions from mempool to include in blocks

**Transaction lifecycle:**
```
1. User creates transaction → Signs with Dilithium private key
2. Broadcasts to network → Sent to connected nodes
3. Enters mempool → Waits for miner to pick it up
4. Miner includes in block → Transaction gets confirmed
5. Block is mined → Transaction is now permanent
```

**Mempool prioritization (how miners choose transactions):**
```
Fee Rate = Transaction Fee / Transaction Size

Higher fee rate → Higher priority → Faster confirmation

Example:
├─ Transaction A: 0.001 DIL fee / 5 KB = 0.0002 DIL/KB
└─ Transaction B: 0.002 DIL fee / 4 KB = 0.0005 DIL/KB ← Mined first
```

---

## 3.5 Consensus: How the Network Agrees

### The Double-Spend Problem

**Without blockchain:**
```
Alice has 10 DIL

She sends 10 DIL to Bob   ┐
At the same time           ├─ Which is valid?
She sends 10 DIL to Charlie┘

Without consensus, both could be accepted (Alice spends 10 DIL twice!)
```

**Blockchain solution:**
```
1. Both transactions broadcast to network
2. Miners see both, include only ONE in a block
3. Whichever gets mined first becomes "truth"
4. The other transaction is rejected (conflicts with confirmed TX)
```

---

### Proof-of-Work: The Consensus Mechanism

**How Dilithion achieves consensus:**

1. **Mining creates blocks**
   - Miners compete to find valid block hash
   - Requires computational work (RandomX)
   - Winner broadcasts block to network

2. **Longest chain rule**
   - Network accepts the chain with most cumulative work
   - If two miners mine simultaneously → Temporary fork
   - Eventually one chain becomes longer → Network converges

3. **Difficulty adjustment**
   - Target: 1 block every 2 minutes
   - Every 2,016 blocks (~2.8 days), difficulty adjusts
   - Keeps block time consistent despite changing hashrate

---

## 3.6 Network Propagation

### How Blocks Spread Through the Network

**When a block is mined:**
```
Miner A finds block
    ↓ Broadcasts to peers
Node B, Node C, Node D receive block
    ↓ Validate block
    ↓ If valid, broadcast to THEIR peers
Node E, F, G, H, I, J receive block
    ↓ Entire network converges

Time to propagate: Usually seconds
```

**What nodes validate:**
- Block hash meets difficulty target
- All transactions are valid (Dilithium signatures check out)
- Block doesn't contain double-spends
- Block size within limits
- Timestamp is reasonable
- Previous block hash exists

**If validation fails → Block is rejected**

---

## 3.7 Quiz: Test Your Knowledge

**Question 1:** What makes a blockchain immutable (unchangeable)?

a) The government protects it
b) Each block references the previous block's hash
c) It's stored on encrypted servers
d) Quantum computers protect it

<details>
<summary>Answer</summary>
**b) Each block references the previous block's hash**

Changing any historical block changes its hash, which breaks the chain (next block points to the OLD hash). To change history, you'd need to remine every subsequent block, which is computationally infeasible.
</details>

---

**Question 2:** What is a UTXO?

a) A type of cryptocurrency
b) An unspent transaction output that can be spent
c) A mining algorithm
d) A quantum-resistant signature

<details>
<summary>Answer</summary>
**b) An unspent transaction output that can be spent**

UTXO model tracks individual outputs rather than account balances. Your balance is the sum of all UTXOs locked to your public keys.
</details>

---

**Question 3:** What happens when two miners find a block simultaneously?

a) Both blocks are rejected
b) The first one broadcast wins
c) Temporary fork; longest chain eventually wins
d) The network shuts down

<details>
<summary>Answer</summary>
**c) Temporary fork; longest chain eventually wins**

This is normal! The network temporarily has two competing chains. Whichever gets the next block first becomes the "longest chain" and the network converges on that one.
</details>

---

**Question 4:** What determines which transactions get mined first?

a) First come, first served
b) Largest transactions
c) Fee rate (fee per KB)
d) Random selection

<details>
<summary>Answer</summary>
**c) Fee rate (fee per KB)**

Miners are incentivized to maximize fees. They prioritize transactions with highest fee rate (fee divided by transaction size in bytes).
</details>

---

## Module 3 Complete! 🎉

**You've learned:**
✅ What a blockchain is and why it's immutable
✅ How blocks and transactions are structured
✅ The UTXO model for tracking coin ownership
✅ How Dilithium signatures verify transaction ownership
✅ The mempool and transaction prioritization
✅ How proof-of-work consensus prevents double-spending
✅ How blocks propagate through the network

**Next Module:** Dilithion's Specific Architecture

---

# Module 4: Dilithion's Architecture

**Duration:** 30 minutes
**What You'll Learn:** How Dilithion implements its quantum-safe blockchain

---

## 4.1 Dilithion's Design Philosophy

### The Three Pillars

```
┌─────────────────────────────────────┐
│   1. QUANTUM RESISTANCE             │
│   Future-proof cryptography         │
│   Built-in from genesis, not added  │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│   2. FAIR DISTRIBUTION              │
│   CPU mining (ASIC-resistant)       │
│   No premine, no ICO, no insiders   │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│   3. SIMPLICITY & SECURITY          │
│   Bitcoin-inspired design           │
│   Proven architecture, not complex  │
└─────────────────────────────────────┘
```

**Dilithion follows Bitcoin's proven model:**
- UTXO transaction model
- Proof-of-Work consensus
- Fixed supply (21 million)
- Halving every 210,000 blocks
- Decentralized network

**Key difference:** Post-quantum cryptography from day one.

---

## 4.2 Dilithion's Cryptographic Stack

### Complete Technical Specification

| Component | Technology | Quantum-Safe? | Standard |
|-----------|-----------|---------------|----------|
| **Signatures** | CRYSTALS-Dilithium3 | ✅ Yes | NIST FIPS 204 |
| **Hashing** | SHA-3 (Keccak-256) | ✅ Yes | NIST FIPS 202 |
| **Mining** | RandomX | ⚪ Neutral | Monero (proven) |
| **Key Derivation** | PBKDF2-HMAC-SHA3 | ✅ Yes | NIST approved |
| **Address Encoding** | Base58Check | ⚪ Neutral | Bitcoin-style |

**Legend:**
- ✅ Quantum-resistant (safe from Shor's/Grover's algorithms)
- ⚪ Quantum-neutral (quantum doesn't provide advantage)

---

## 4.3 Block Structure

### Dilithion Block Anatomy

```cpp
Block {
  // Header (80 bytes + 32 bytes SHA-3 hash)
  int32_t version = 1;
  uint256 hashPrevBlock;      // SHA-3 hash of previous block
  uint256 hashMerkleRoot;     // SHA-3 Merkle root of transactions
  uint32_t timestamp;         // Unix timestamp
  uint32_t difficulty;        // Compact difficulty target
  uint64_t nonce;             // RandomX nonce

  // Body (variable size)
  vector<Transaction> vtx;    // All transactions
}
```

**Key differences from Bitcoin:**
- Uses SHA-3 instead of SHA-256
- RandomX nonce (8 bytes) instead of SHA-256 nonce (4 bytes)
- Larger average block size due to Dilithium signatures

---

### Block Size Comparison

**Bitcoin block:**
```
Average transaction size: ~250 bytes (ECDSA signature: 72 bytes)
Transactions per block: ~2,000
Average block size: ~500 KB
```

**Dilithion block:**
```
Average transaction size: ~4,000 bytes (Dilithium signature: 3,309 bytes)
Transactions per block: ~125
Average block size: ~500 KB (similar!)
```

**Despite 46x larger signatures, blocks are similar size because:**
- Fewer transactions per block
- 2-minute block time (vs Bitcoin's 10 min) = more frequent blocks
- Throughput is comparable overall

---

## 4.4 Transaction Structure

### Dilithion Transaction Anatomy

```cpp
Transaction {
  int32_t version = 1;

  // Inputs (spending UTXOs)
  vector<TxIn> vin;
    TxIn {
      uint256 prevout_hash;    // Which previous transaction
      uint32_t prevout_n;      // Which output of that transaction
      vector<uint8_t> signature; // Dilithium signature (3,309 bytes!)
      uint32_t sequence;
    }

  // Outputs (creating new UTXOs)
  vector<TxOut> vout;
    TxOut {
      int64_t value;           // Amount in satoshis (0.00000001 DIL)
      vector<uint8_t> scriptPubKey; // Locking script (pubkey hash)
    }

  uint32_t locktime;           // When TX can be mined
}
```

**Size breakdown:**
```
ECDSA transaction (Bitcoin):
├─ Overhead: ~40 bytes
├─ Input: ~148 bytes (signature: 72 bytes)
├─ Output: ~34 bytes
└─ Total: ~250 bytes typical

Dilithium transaction (Dilithion):
├─ Overhead: ~40 bytes
├─ Input: ~3,400 bytes (signature: 3,309 bytes!)
├─ Output: ~34 bytes
└─ Total: ~3,500 bytes typical
```

**This is the tradeoff for quantum resistance.**

---

## 4.5 Address Generation

### From Private Key to Public Address

**Step-by-step process:**

```
1. Generate Dilithium key pair
   ├─ Private key: 4,032 bytes (keep secret!)
   └─ Public key: 1,952 bytes

2. Hash public key with SHA-3-256
   └─ Result: 32 bytes

3. Hash again with SHA-3-256 (double-hash)
   └─ Result: 32 bytes

4. Take first 20 bytes
   └─ Result: 20-byte public key hash

5. Add version byte (0x1E for mainnet)
   └─ Result: 21 bytes

6. Compute checksum (SHA-3 hash, take first 4 bytes)
   └─ Append to address

7. Base58 encode
   └─ Final address: "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV"
```

**Address format:**
```
Mainnet addresses: Start with "D"
Testnet addresses: Start with "T"
```

**Example addresses:**
```
D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV  ← Valid mainnet
T7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV  ← Valid testnet
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  ← Bitcoin (starts with 1)
```

---

## 4.6 Dilithion's Consensus Parameters

### Economic Parameters (Bitcoin-Inspired)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Total Supply** | 21,000,000 DIL | Proven scarcity model |
| **Initial Reward** | 50 DIL | Same as Bitcoin |
| **Block Time** | 2 minutes | Faster confirmation than BTC |
| **Halving Interval** | 210,000 blocks | ~8 months per halving |
| **Difficulty Adjustment** | Every 2,016 blocks | ~2.8 days |

### Fee Model

**Minimum transaction fee:**
```
Base fee: 0.0005 DIL (fixed)
Size fee: 25 satoshis per byte (0.00000025 DIL/byte)

Example transaction (3,500 bytes):
├─ Base: 0.0005 DIL
├─ Size: 3,500 × 0.00000025 = 0.000875 DIL
└─ Total: 0.001375 DIL (~$0.01 at $10/DIL)
```

**Why higher fees than Bitcoin?**
- Larger transaction sizes (Dilithium signatures)
- Need to incentivize miners despite larger blocks
- Still affordable for everyday use

---

## 4.7 Genesis Block

### The First Block (January 1, 2026 00:00:00 UTC)

```cpp
Genesis Block:
├─ Timestamp: 1767225600 (Jan 1, 2026 00:00:00 UTC)
├─ Difficulty: 0x1d00ffff (Bitcoin's genesis difficulty)
├─ Nonce: [To be determined by mining on Nov 25, 2025]
├─ Merkle Root: [Computed from coinbase transaction]
└─ Coinbase message:
    "The Guardian 01/Jan/2026: Quantum computing advances threaten
     cryptocurrency security - Dilithion launches with post-quantum
     protection for The People's Coin"
```

**Significance:**
- Timestamp marks symbolic new year launch
- Coinbase message references quantum threat (like Bitcoin's 2009 bank bailout message)
- Fixed difficulty ensures fair start
- No premine - genesis block mined publicly

---

## 4.8 Quiz: Test Your Knowledge

**Question 1:** What is Dilithion's block time?

a) 10 minutes (like Bitcoin)
b) 30 seconds
c) 2 minutes
d) 1 minute

<details>
<summary>Answer</summary>
**c) 2 minutes**

Dilithion uses 2-minute blocks (5x faster than Bitcoin's 10 minutes) to balance confirmation speed with network propagation time for larger Dilithium signatures.
</details>

---

**Question 2:** Why are Dilithion transactions larger than Bitcoin transactions?

a) Dilithion is inefficient
b) Dilithium signatures are 46x larger than ECDSA signatures
c) Dilithion includes more metadata
d) It's a bug

<details>
<summary>Answer</summary>
**b) Dilithium signatures are 46x larger than ECDSA signatures**

CRYSTALS-Dilithium3 signatures are ~3,309 bytes vs ECDSA's 72 bytes. This is the fundamental tradeoff for quantum resistance using lattice cryptography.
</details>

---

**Question 3:** What is Dilithion's total supply?

a) 21 billion
b) Unlimited
c) 21 million
d) 100 million

<details>
<summary>Answer</summary>
**c) 21 million**

Following Bitcoin's proven scarcity model, Dilithion has a fixed supply of 21 million DIL with halving every 210,000 blocks.
</details>

---

**Question 4:** What do Dilithion mainnet addresses start with?

a) 1 (like Bitcoin)
b) D
c) Q (for quantum)
d) 0x

<details>
<summary>Answer</summary>
**b) D**

Dilithion mainnet addresses start with "D" (for Dilithion), while testnet addresses start with "T". This is determined by the version byte in the Base58Check encoding.
</details>

---

## Module 4 Complete! 🎉

**You've learned:**
✅ Dilithion's design philosophy (quantum resistance + fair distribution + simplicity)
✅ Complete cryptographic stack (Dilithium3 + SHA-3 + RandomX)
✅ Block and transaction structure with Dilithium signatures
✅ Address generation process (public key → SHA-3 → Base58)
✅ Consensus parameters (21M supply, 2-min blocks, halving)
✅ Genesis block details (Jan 1, 2026 launch)

**Next Module:** Mining & Proof-of-Work

---

# Module 5: Mining & Proof-of-Work

**Duration:** 30 minutes
**What You'll Learn:** How RandomX mining works and why it's CPU-friendly

---

## 5.1 What is Mining?

### The Purpose of Mining

**Mining serves three critical functions:**

1. **Secure the network**
   - Makes attacking the blockchain computationally expensive
   - Would-be attacker needs 51% of network hashrate

2. **Reach consensus**
   - Determines which transactions are confirmed
   - Prevents double-spending

3. **Distribute new coins**
   - Fair way to release coins into circulation
   - Incentivizes miners to secure network

---

### How Proof-of-Work Mining Works

**The challenge:**
```
Find a nonce (random number) such that:

SHA-3( Block Header + nonce ) < difficulty_target

Example:
Target:  0000000000ffff....  (lots of leading zeros)
Try #1:  9a3b4c5d6e7f8...  ❌ Too high
Try #2:  5f4e3d2c1b0a9...  ❌ Too high
Try #3:  00000000001234...  ✅ Success! Block found
```

**Key insight:** There's no shortcut. You must try random nonces until you get lucky.

**Difficulty adjusts to keep block time at ~2 minutes:**
- More miners → Increase difficulty
- Fewer miners → Decrease difficulty

---

## 5.2 RandomX: CPU-Friendly Mining

### Why Not Use SHA-256 (like Bitcoin)?

**Bitcoin's problem:**
```
2009: CPU mining (everyone can participate)
2010: GPU mining invented (10x faster than CPUs)
2013: ASIC mining invented (1000x faster than GPUs)
2025: Only ASIC manufacturers control Bitcoin mining
```

**Result:** Centralization, expensive hardware, high barrier to entry

**Dilithion's solution: RandomX**
- Designed to be ASIC-resistant
- Optimized for CPU architecture
- Memory-hard (requires 2GB RAM per thread)
- GPUs/ASICs have no significant advantage

---

### How RandomX Works

**RandomX is a Random Code Execution PoW:**

```
1. Generate random program from seed
   ├─ Seed = Block header
   └─ Program = Hundreds of random CPU instructions

2. Execute program in RandomX VM
   ├─ Integer operations
   ├─ Floating-point operations
   ├─ Memory accesses (2GB dataset)
   └─ Branch predictions

3. Output = Hash result
   └─ Check if hash < difficulty target
```

**Why this works:**
- **Modern CPUs excel at this** - RandomX uses all CPU features
- **ASICs can't specialize** - Program is random each time
- **Memory-hard** - Requires 2GB per thread (expensive for ASICs)
- **GPU inefficient** - Random branching kills GPU parallelism

---

### RandomX Performance

**Expected hash rates (per core):**

| CPU Model | Cores | Hash Rate | Total |
|-----------|-------|-----------|-------|
| Intel i9-12900K | 16 | ~65 H/s | ~1,040 H/s |
| AMD Ryzen 9 5900X | 12 | ~65 H/s | ~845 H/s |
| Intel i7-12700 | 12 | ~65 H/s | ~780 H/s |
| AMD Ryzen 7 5800X | 8 | ~65 H/s | ~560 H/s |
| Basic laptop (4 cores) | 4 | ~65 H/s | ~260 H/s |

**Key insight:** Even low-end CPUs can mine competitively. A laptop can achieve 25-40% of a high-end desktop's hashrate.

---

## 5.3 Mining Economics

### Block Rewards & Emission Schedule

**Initial reward:** 50 DIL per block
**Halving:** Every 210,000 blocks (~8 months)

| Era | Blocks | Duration | Reward | Coins Mined | % of Supply |
|-----|--------|----------|--------|-------------|-------------|
| 1 | 0 - 209,999 | ~8 months | 50 DIL | 10,500,000 | 50% |
| 2 | 210,000 - 419,999 | ~8 months | 25 DIL | 5,250,000 | 25% |
| 3 | 420,000 - 629,999 | ~8 months | 12.5 DIL | 2,625,000 | 12.5% |
| ... | ... | ... | ... | ... | ... |
| 21+ | After ~14 years | Forever | 0 DIL | 0 | 0% |

**Total supply:** 21,000,000 DIL (exact, like Bitcoin)

---

### Mining Profitability

**Factors affecting profitability:**

1. **Network hashrate**
   - More miners → Lower chance of finding block
   - Your % of network hashrate = Your % of rewards

2. **Electricity cost**
   - RandomX: ~15-20W per core
   - Example: 8-core CPU = ~120-160W
   - At $0.10/kWh: ~$0.012-0.016 per hour

3. **DIL price**
   - Block reward: 50 DIL
   - If DIL = $1: Block worth $50
   - If DIL = $10: Block worth $500

4. **Hardware**
   - CPU mining: Use existing hardware (low investment)
   - No need for expensive ASICs

---

**Example calculation:**

```
Network hashrate: 10,000 H/s
Your hashrate: 500 H/s (8-core CPU)
Your % of network: 5%

Expected blocks per day:
- Network: 720 blocks (1 block/2 min = 720/day)
- Your share: 720 × 0.05 = 36 blocks/day

Revenue per day:
- Blocks: 36 × 50 DIL = 1,800 DIL/day
- Value at $1/DIL: $1,800/day
- Value at $0.10/DIL: $180/day

Electricity cost:
- 160W × 24 hours = 3.84 kWh/day
- At $0.10/kWh: $0.38/day

Profit: $180 - $0.38 = $179.62/day (at $0.10/DIL)
```

**Reality check:** Early days will have low network hashrate (high rewards). As more miners join, profitability decreases (economics).

---

## 5.4 Mining Software

### How to Mine Dilithion

**Option 1: Solo Mining (Built-in)**
```bash
# Start node with mining enabled
./dilithion-node --mine --threads=8

# Your node will:
├─ Download blockchain
├─ Validate all blocks
├─ Mine new blocks with 8 CPU threads
└─ If you find a block, you get full 50 DIL reward!
```

**Pros:**
- Keep full block reward
- Support decentralization
- No pool fees

**Cons:**
- Irregular income (might find 0 blocks for days, then 3 in a day)
- Need patience

---

**Option 2: Pool Mining (Coming Soon)**
```bash
# Connect to mining pool
./dilithion-miner --pool=pool.dilithion.org --threads=8

# Pool will:
├─ Coordinate mining with other miners
├─ Share block rewards proportionally
└─ Pay you daily based on contributed hashrate
```

**Pros:**
- Regular, predictable income
- Lower variance (steady payouts)

**Cons:**
- Pool fees (typically 1-2%)
- Slight centralization
- Must trust pool operator

---

### Mining Best Practices

**Hardware:**
- ✅ Use modern CPUs (better RandomX performance)
- ✅ Ensure good cooling (mining generates heat)
- ✅ 2GB RAM per thread minimum
- ❌ Don't mine on laptops continuously (overheating risk)
- ❌ Don't use GPUs (inefficient for RandomX)

**Software:**
- ✅ Keep node updated to latest version
- ✅ Monitor temperature (use tools like HWMonitor)
- ✅ Start with fewer threads, gradually increase
- ❌ Don't overclock excessively (instability)

**Economics:**
- ✅ Calculate profitability based on your electricity cost
- ✅ Consider mining as supporting the network (not get-rich-quick)
- ✅ Start small, scale if profitable
- ❌ Don't invest more than you can afford to lose

---

## 5.5 Network Security

### 51% Attack

**What is it?**
```
If an attacker controls >50% of network hashrate, they can:
├─ Double-spend (send coins twice)
├─ Prevent confirmations
└─ Reorganize recent blocks

They CANNOT:
├─ Steal coins from other people's wallets (need private keys)
├─ Change consensus rules (other nodes would reject)
└─ Create coins out of thin air (reward limits are enforced)
```

**Why RandomX helps:**
- Anyone with a CPU can mine
- Hard to monopolize hashrate (no ASIC manufacturers)
- Distributed mining = Better security

**Cost of 51% attack:**
```
Assume network hashrate: 100,000 H/s
To control 51%: Need 51,000 H/s
CPUs needed: 51,000 / 65 = ~785 high-end CPUs
Cost: $500/CPU × 785 = $392,500

Plus electricity: ~125 kW continuous power

This assumes you can even acquire that many CPUs without raising prices.
Attack is expensive and detectable.
```

---

## 5.6 Quiz: Test Your Knowledge

**Question 1:** What is the purpose of mining?

a) Just to create new coins
b) Secure network, reach consensus, distribute coins
c) Heat your room
d) Test your CPU

<details>
<summary>Answer</summary>
**b) Secure network, reach consensus, distribute coins**

Mining serves three functions: (1) Makes attacking the blockchain expensive, (2) Determines which transactions are confirmed, (3) Fairly distributes new coins into circulation.
</details>

---

**Question 2:** Why is RandomX ASIC-resistant?

a) It bans ASICs in the code
b) It uses random CPU instructions and is memory-hard
c) It's encrypted
d) It's quantum-resistant

<details>
<summary>Answer</summary>
**b) It uses random CPU instructions and is memory-hard**

RandomX generates random programs that utilize all CPU features (integer, floating-point, memory, branches). This makes specialized ASICs inefficient, and the 2GB memory requirement makes them expensive.
</details>

---

**Question 3:** How often does Dilithion's block reward halve?

a) Every year
b) Every 4 years (like Bitcoin)
c) Every 210,000 blocks (~8 months)
d) Never

<details>
<summary>Answer</summary>
**c) Every 210,000 blocks (~8 months)**

Dilithion follows Bitcoin's 210,000 block halving interval, but with 2-minute blocks instead of 10-minute, this happens ~every 8 months instead of 4 years.
</details>

---

**Question 4:** What is a 51% attack?

a) When 51% of users sell their coins
b) When someone controls majority hashrate and can double-spend
c) When 51% of nodes go offline
d) When a quantum computer attacks

<details>
<summary>Answer</summary>
**b) When someone controls majority hashrate and can double-spend**

With >50% of network hashrate, an attacker can reorganize recent blocks and double-spend coins. However, they still cannot steal others' coins (need private keys) or create coins arbitrarily (consensus rules enforced by nodes).
</details>

---

## Module 5 Complete! 🎉

**You've learned:**
✅ What mining is and why it's necessary
✅ How Proof-of-Work prevents double-spending
✅ Why RandomX is CPU-friendly and ASIC-resistant
✅ Expected mining performance (65 H/s per CPU core)
✅ Mining economics and profitability calculations
✅ Solo vs pool mining
✅ 51% attack and network security

**Next Module:** Wallet Security & Best Practices

---

# Module 6: Wallet Security & Best Practices

**Duration:** 30 minutes
**What You'll Learn:** How to keep your Dilithion safe

---

## 6.1 What is a Wallet?

### Wallet Basics

**A wallet is NOT:**
- ❌ A place where coins are stored
- ❌ A physical container
- ❌ An account on a server

**A wallet IS:**
- ✅ A collection of private keys
- ✅ Software to manage keys and sign transactions
- ✅ An interface to the blockchain

**The coins exist on the blockchain. The wallet just holds the keys.**

```
Blockchain:
├─ Output 1: 10 DIL locked to Public Key A
├─ Output 2: 5 DIL locked to Public Key B
└─ Output 3: 3 DIL locked to Public Key C

Your Wallet:
├─ Private Key A (controls 10 DIL)
├─ Private Key B (controls 5 DIL)
└─ Balance: 15 DIL
```

**If you lose your private keys, you lose access to your coins forever.**
**If someone steals your private keys, they steal your coins forever.**

---

## 6.2 Types of Wallets

### 1. Full Node Wallet (Dilithion-node)

**What it is:**
- Downloads entire blockchain
- Validates all transactions
- Fully trustless (doesn't rely on third parties)

**Pros:**
- ✅ Maximum security and privacy
- ✅ Supports the network
- ✅ Full validation of all rules

**Cons:**
- ❌ Requires significant disk space
- ❌ Slow initial sync
- ❌ Must stay online to sync

**When to use:** If you're serious about Dilithion and have the resources.

---

### 2. Lightweight Wallet (Coming Soon)

**What it is:**
- Doesn't download full blockchain
- Relies on full nodes for blockchain data
- Only stores your keys

**Pros:**
- ✅ Fast startup
- ✅ Low disk space
- ✅ Mobile-friendly

**Cons:**
- ❌ Less private (SPV servers see your addresses)
- ❌ Must trust servers for blockchain data
- ❌ Doesn't validate all consensus rules

**When to use:** For everyday transactions, mobile use.

---

### 3. Paper Wallet

**What it is:**
- Private key printed/written on paper
- Completely offline (cold storage)

**Pros:**
- ✅ Immune to hacking (offline)
- ✅ Simple backup

**Cons:**
- ❌ Paper can be damaged/destroyed
- ❌ Must import to spend (exposes key)
- ❌ Not user-friendly

**When to use:** Long-term storage of large amounts.

---

### 4. Hardware Wallet (Future Support)

**What it is:**
- Dedicated device (like Ledger, Trezor)
- Keys never leave device
- Signs transactions internally

**Pros:**
- ✅ Very secure (keys never exposed)
- ✅ User-friendly
- ✅ Can use on compromised computers

**Cons:**
- ❌ Costs money ($50-200)
- ❌ Requires Dilithion support (not yet available)

**When to use:** When hardware wallet manufacturers add Dilithium support.

---

## 6.3 Wallet Encryption

### How Dilithion Protects Your Keys

**Unencrypted wallet (DEFAULT IS UNSAFE):**
```
wallet.dat file:
├─ Private Key 1: [4032 bytes in plaintext]
├─ Private Key 2: [4032 bytes in plaintext]
└─ If attacker gets this file → Your coins are stolen
```

**Encrypted wallet (ALWAYS DO THIS):**
```
wallet.dat file:
├─ Encrypted Key 1: [AES-256 encrypted]
├─ Encrypted Key 2: [AES-256 encrypted]
├─ Salt: [Random data]
└─ Encrypted with password → Attacker needs password to decrypt
```

---

### Encryption Process

**Step 1: Encrypt your wallet**
```bash
# Via RPC
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"encryptwallet","params":["YourStrongPassword123!"],"id":1}'

# Wallet is now encrypted
# Node will restart
```

**Step 2: Unlock for transactions**
```bash
# Unlock for 300 seconds
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"walletpassphrase","params":["YourStrongPassword123!", 300],"id":1}'

# Send transaction within 300 seconds
# Wallet auto-locks after timeout
```

---

### Password Best Practices

**Good passwords:**
✅ At least 16 characters
✅ Mix of uppercase, lowercase, numbers, symbols
✅ Unique (not used elsewhere)
✅ Random (use password generator)
✅ Example: `K9$mPz2!vQx7@nL5wR3hY`

**Bad passwords:**
❌ Short (< 12 characters)
❌ Dictionary words
❌ Personal info (birthdays, names)
❌ Reused from other sites
❌ Example: `password123`, `dilithion2026`

**CRITICAL:** If you forget your password, your coins are GONE FOREVER. No recovery possible.

**Backup your password:**
- Write on paper, store in safe
- Use encrypted password manager
- Split into parts (family members each hold part)

---

## 6.4 Backup & Recovery

### The 3-2-1 Backup Rule

**For your wallet:**
- **3** copies (original + 2 backups)
- **2** different media types (USB + cloud OR USB + paper)
- **1** offsite (not in same location)

---

### What to Backup

**Essential:**
1. **Encrypted wallet file** (`wallet.dat`)
2. **Password** (written down, stored safely)

**Optional but recommended:**
3. **Recovery phrase** (if wallet supports BIP39 - future feature)
4. **List of addresses** (to verify backup worked)

---

### Backup Process

**Step 1: Encrypt wallet (if not already encrypted)**

**Step 2: Backup wallet file**
```bash
# Locate wallet file
# Linux: ~/.dilithion/wallet.dat
# Windows: C:\Users\YourName\AppData\Roaming\Dilithion\wallet.dat
# macOS: ~/Library/Application Support/Dilithion/wallet.dat

# Copy to USB drive
cp ~/.dilithion/wallet.dat /media/usb/dilithion-backup-2026-01-01.dat

# Copy to encrypted cloud storage
# Use Tresorit, SpiderOak, or encrypt manually with GPG first
```

**Step 3: Test backup**
```bash
# On a TEST computer (not your main one):
1. Install Dilithion node
2. Stop node
3. Replace wallet.dat with backup copy
4. Start node
5. Check balance matches
6. If successful, backup is valid!
```

**Step 4: Secure storage**
```
USB Backup 1: Fireproof safe at home
USB Backup 2: Bank safety deposit box
Password: Paper in separate safe OR encrypted password manager
```

---

## 6.5 Common Security Threats

### 1. Malware / Keyloggers

**Threat:**
- Malware on your computer records keystrokes
- Captures your wallet password when you type it
- Steals wallet.dat file

**Protection:**
- ✅ Use antivirus software
- ✅ Don't download suspicious files
- ✅ Keep OS updated
- ✅ Use hardware wallet (when available)
- ✅ Consider air-gapped computer for large amounts

---

### 2. Phishing

**Threat:**
- Fake website looks like official Dilithion site
- Tricks you into entering private key or password
- Steals your coins

**Protection:**
- ✅ Bookmark official site (dilithion.org)
- ✅ Check URL carefully (dilithion.org NOT dilithioon.org)
- ✅ Never enter private key on websites
- ✅ Use official wallet software only

---

### 3. Physical Theft

**Threat:**
- Someone steals your laptop/USB with wallet
- If unencrypted, they have your coins
- If encrypted, they'll try to crack password

**Protection:**
- ✅ Encrypt wallet with strong password
- ✅ Encrypt entire disk (BitLocker, FileVault, LUKS)
- ✅ Don't store large amounts on laptop
- ✅ Use cold storage for savings

---

### 4. Social Engineering

**Threat:**
- Attacker impersonates support/dev team
- Asks for your private key "to help you"
- Tricks you into sending coins to "verify" address

**Protection:**
- ✅ NEVER share private keys with anyone
- ✅ NEVER share wallet password
- ✅ Official team will NEVER ask for keys
- ✅ If uncertain, ask in public Discord (not DMs)

---

## 6.6 Best Practices Summary

### Security Checklist

**Before holding significant DIL:**
- [ ] Wallet is encrypted with strong (16+ char) password
- [ ] Password written down and stored in safe
- [ ] Wallet backed up to 2+ locations
- [ ] Backup tested and verified
- [ ] Computer has antivirus and is updated
- [ ] Full disk encryption enabled
- [ ] Know how to restore from backup

**Daily operations:**
- [ ] Only unlock wallet when needed
- [ ] Lock wallet after transactions
- [ ] Keep wallet software updated
- [ ] Check for security announcements
- [ ] Use separate wallet for daily use (hot) vs savings (cold)

**Advanced:**
- [ ] Use separate computer for large amounts
- [ ] Consider multisig (when available)
- [ ] Use hardware wallet (when Dilithium supported)
- [ ] Regular security audits of your setup

---

## 6.7 Quiz: Test Your Knowledge

**Question 1:** What does a wallet actually store?

a) Your coins
b) Your private keys
c) Your transaction history
d) Your username and password

<details>
<summary>Answer</summary>
**b) Your private keys**

Coins exist on the blockchain. The wallet stores private keys that allow you to create signatures proving ownership and spend those coins.
</details>

---

**Question 2:** What happens if you forget your wallet encryption password?

a) You can reset it via email
b) Dilithion support can recover it
c) Your coins are lost forever
d) You can use your recovery phrase

<details>
<summary>Answer</summary>
**c) Your coins are lost forever**

There is NO password recovery. This is by design - no centralized authority can access your wallet. If you forget your password, the encrypted keys are unrecoverable. Always backup your password securely!
</details>

---

**Question 3:** What is the 3-2-1 backup rule?

a) 3 passwords, 2 wallets, 1 computer
b) 3 copies, 2 media types, 1 offsite
c) 3 backups per month
d) 3 signatures required

<details>
<summary>Answer</summary>
**b) 3 copies, 2 media types, 1 offsite**

Best practice: Keep 3 total copies of your wallet, on 2 different types of media (USB + cloud), with 1 stored offsite (not at your home).
</details>

---

**Question 4:** Should you ever share your private key?

a) Yes, with Dilithion support if you need help
b) Yes, with your wallet provider
c) Yes, with trusted family members
d) NO, NEVER share your private key with ANYONE

<details>
<summary>Answer</summary>
**d) NO, NEVER share your private key with ANYONE**

Anyone with your private key can steal your coins. No legitimate service will ever ask for it. This includes Dilithion developers, support, exchanges - NO ONE should ever need your private key except your wallet software.
</details>

---

## Module 6 Complete! 🎉

**You've learned:**
✅ What a wallet is (key storage, not coin storage)
✅ Types of wallets (full node, lightweight, paper, hardware)
✅ How wallet encryption protects your keys
✅ Password best practices
✅ The 3-2-1 backup rule
✅ Common security threats and how to protect against them
✅ Security checklist for holding DIL safely

**Next Module:** The Future of Quantum-Safe Crypto

---

# Module 7: The Future of Quantum-Safe Crypto

**Duration:** 30 minutes
**What You'll Learn:** Where cryptocurrency is heading in the quantum era

---

## 7.1 The Quantum Computing Timeline

### Current State (2025)

**What exists today:**
- Quantum computers with 100-1,000 qubits (IBM, Google, IonQ)
- Quantum supremacy demonstrated (2019)
- Error rates still high (noisy intermediate-scale quantum - NISQ era)
- Cannot break cryptography yet

**Key limitation:** Need ~4,000 logical qubits to break RSA-2048 or ECDSA-256

---

### Near Future (2030-2035)

**Expert predictions:**
```
Timeline estimates from leading researchers:

Conservative: 2035-2040
├─ Focus on error correction first
└─ Slow but steady progress

Moderate: 2030-2035  ← Most experts agree
├─ Continued Moore's Law-like growth
└─ Cryptographically relevant QC likely

Aggressive: 2027-2030
├─ Major breakthroughs possible
└─ Some predict faster progress
```

**What this means:**
- Bitcoin/Ethereum vulnerable within 5-10 years
- "Store now, decrypt later" attacks already underway
- Post-quantum migration urgency increasing

---

## 7.2 Migration Challenges for Existing Cryptocurrencies

### Bitcoin's Quantum Dilemma

**The problem:**
```
Bitcoin launched: 2009 (16 years old)
Codebase: Designed for ECDSA
Network: $1+ trillion value at stake
Users: 100+ million people

Migrating to post-quantum crypto requires:
├─ Hard fork (network-wide upgrade)
├─ All users update software
├─ Move coins to new quantum-safe addresses
├─ Abandon old addresses (or they're vulnerable)
└─ Coordination nightmare
```

---

### The Migration Scenarios

**Scenario 1: Proactive Migration (Best Case)**
```
2026-2028: Bitcoin devs add PQ signatures (soft fork if possible)
2028-2030: Users voluntarily migrate coins to PQ addresses
2030+: Quantum computers arrive
Result: Bitcoin survives, but painful transition
```

**Scenario 2: Reactive Migration (Medium Case)**
```
2030: Quantum computers exist but not widely accessible
2030-2032: Panic migration as threat becomes real
2032+: Race against quantum attacks
Result: Chaotic but survives if timeline allows
```

**Scenario 3: Too Late (Worst Case)**
```
2028: Unexpected quantum breakthrough
Bitcoin unprepared, no PQ solution ready
Massive theft as old addresses compromised
Result: Bitcoin value collapses
```

---

### Why Dilithion Has an Advantage

**Built quantum-safe from genesis:**
```
✅ No migration needed
✅ No hard fork risks
✅ No legacy vulnerable addresses
✅ Future-proof by design
```

**Analogy:**
```
Bitcoin: Building a house, then retrofitting earthquake protection
Dilithion: Building with earthquake protection from the foundation
```

---

## 7.3 NIST's Influence on Crypto Industry

### The Post-Quantum Standards

**NIST's selected algorithms (2022):**

1. **CRYSTALS-Dilithium** (Signatures) ← Dilithion uses this
   - Primary recommendation for digital signatures
   - Fastest widespread adoption expected

2. **CRYSTALS-Kyber** (Key Exchange)
   - For encryption (TLS, VPNs)
   - Already being adopted by browsers

3. **SPHINCS+** (Backup Signatures)
   - Stateless hash-based
   - Alternative to lattice schemes

4. **FALCON** (Compact Signatures)
   - Smaller signatures than Dilithium
   - More complex implementation

---

### Industry Adoption Timeline

**Already happening:**
```
2023: Google Chrome tests Kyber for TLS
2024: Apple announces PQ iMessage
2024: Signal adds PQ encryption
2025: Cloudflare deploys PQ by default
```

**What's coming:**
```
2026-2027: Banks migrate to PQ cryptography
2027-2028: Governments mandate PQ for sensitive data
2028-2030: Legacy crypto phase-out begins
2030+: Quantum computers arrive, PQ is standard
```

**Cryptocurrencies are behind:**
- Most still use ECDSA
- Few have concrete PQ plans
- Dilithion is early mover

---

## 7.4 Potential Challenges for Dilithion

### Technical Challenges

**1. Blockchain bloat**
```
Problem: Dilithium signatures are 46x larger
Impact: Blockchain grows faster than Bitcoin

Mitigation strategies:
├─ Pruning (discard old signatures after validation)
├─ Signature aggregation (future research)
├─ Layer 2 solutions (off-chain transactions)
└─ Optimized compression
```

**2. Network bandwidth**
```
Problem: Larger transactions take longer to propagate
Impact: Potential orphan blocks, network delays

Mitigation:
├─ 2-minute block time (buffer for propagation)
├─ Block size limits
└─ Optimized P2P protocol
```

**3. Storage requirements**
```
Problem: Full nodes need more disk space
Impact: Higher barrier for running nodes

Mitigation:
├─ Pruned nodes (store only recent data)
├─ SPV wallets (don't need full chain)
└─ Declining storage costs
```

---

### Economic Challenges

**1. Network effect**
```
Bitcoin: 15+ years of adoption, massive ecosystem
Dilithion: New, unproven network

Challenge: Convincing users to switch
```

**2. Exchange listings**
```
Major exchanges require:
├─ Proven security (audits needed)
├─ Trading volume
├─ User demand
└─ Integration effort (new signature scheme)
```

**3. Merchant adoption**
```
Payment processors must:
├─ Add Dilithium signature support
├─ Integrate new address format
├─ Trust new technology
```

---

### Social Challenges

**1. Education**
```
Most people don't understand:
├─ Quantum threat timeline
├─ Why PQ crypto matters
├─ How Dilithium works
└─ Urgency of migration

Solution: Educational campaigns (like this course!)
```

**2. Trust**
```
New cryptocurrency faces skepticism:
├─ "Why not just use Bitcoin?"
├─ "Quantum computers are far away"
├─ "They'll fix Bitcoin when needed"

Counterargument: Proactive > Reactive
```

**3. Regulatory**
```
Governments may:
├─ Require PQ crypto for financial systems
├─ Or ignore crypto until too late
├─ Or ban crypto entirely (some jurisdictions)
```

---

## 7.5 The Long-Term Vision

### Dilithion's Roadmap

**Year 1 (2026):**
```
✅ Mainnet launch Jan 1, 2026
✅ Build mining community
✅ Achieve network stability
✅ Exchange listings (DEXs first)
✅ Grow user base
```

**Year 2-3 (2027-2028):**
```
├─ Layer 2 solutions (Lightning-style channels)
├─ Smart contract research (simple scripts)
├─ Mobile wallets
├─ Hardware wallet support
├─ Mining pool protocol
└─ Block explorer
```

**Year 4-5 (2029-2030):**
```
├─ As quantum threat materializes:
├─ Bitcoin/Ethereum panic migration
├─ Dilithion positioned as safe haven
├─ Massive awareness campaign
├─ "We told you so" moment
└─ Potential massive adoption
```

**Year 10+ (2035+):**
```
├─ If successful: Standard quantum-safe cryptocurrency
├─ If Bitcoin migrates successfully: Coexist as alternative
├─ If Bitcoin fails: Dilithion as leading crypto
└─ Mission accomplished: Crypto survives quantum era
```

---

### The Bigger Picture

**Dilithion is not just a cryptocurrency - it's:**

1. **A quantum canary**
   - Proving PQ crypto works at scale
   - Testing NIST standards in production
   - Validating Dilithium signature scheme

2. **An educational platform**
   - Teaching about quantum threat
   - Demonstrating post-quantum solutions
   - Preparing users for quantum era

3. **An insurance policy**
   - If Bitcoin fails to migrate in time
   - If quantum breakthrough happens early
   - A quantum-safe alternative exists

4. **A research project**
   - Real-world PQ cryptography deployment
   - Blockchain optimization for large signatures
   - Community-driven innovation

---

## 7.6 How You Can Help

### Support the Mission

**1. Mine Dilithion**
```
├─ Secure the network
├─ Distribute coins fairly
└─ Prove RandomX CPU mining works
```

**2. Educate others**
```
├─ Share this course
├─ Explain quantum threat
├─ Spread awareness
└─ Advocate for PQ adoption
```

**3. Contribute**
```
├─ Code (if developer)
├─ Testing and bug reports
├─ Documentation improvements
└─ Community support
```

**4. Adopt for payments**
```
├─ Accept DIL at your business
├─ Use for transactions
├─ Build ecosystem tools
└─ Create use cases
```

---

## 7.7 Final Quiz: Test Your Comprehensive Knowledge

**Question 1:** When do experts predict quantum computers will threaten current cryptocurrencies?

a) 2025 (now)
b) 2030-2035
c) 2050+
d) Never

<details>
<summary>Answer</summary>
**b) 2030-2035**

Most experts predict cryptographically-relevant quantum computers within 5-10 years. This makes Dilithion's 2026 launch timely - quantum-safe before the threat materializes.
</details>

---

**Question 2:** What is Dilithion's main advantage over Bitcoin in the quantum era?

a) Faster transactions
b) Lower fees
c) Quantum-safe from genesis (no migration needed)
d) Better marketing

<details>
<summary>Answer</summary>
**c) Quantum-safe from genesis (no migration needed)**

Bitcoin must undergo painful migration, risking value and causing chaos. Dilithion is designed quantum-safe from day one - no legacy addresses, no hard fork, no migration.
</details>

---

**Question 3:** Which algorithm does Dilithion use for signatures?

a) ECDSA (like Bitcoin)
b) RSA
c) CRYSTALS-Dilithium3
d) SPHINCS+

<details>
<summary>Answer</summary>
**c) CRYSTALS-Dilithium3**

NIST-standardized post-quantum signature scheme based on Module-LWE lattice problem. Selected after 6-year competition as the primary recommendation for digital signatures.
</details>

---

**Question 4:** What is the main tradeoff for quantum resistance in Dilithion?

a) Slower transaction speed
b) Higher fees
c) Larger signatures (46x bigger than ECDSA)
d) Centralization

<details>
<summary>Answer</summary>
**c) Larger signatures (46x bigger than ECDSA)**

Dilithium signatures are ~3,309 bytes vs ECDSA's 72 bytes. This causes larger transactions and blockchain, but provides quantum safety. Signing/verification speed is comparable.
</details>

---

**Question 5:** Why is CPU mining (RandomX) important for Dilithion?

a) It's cheaper
b) It's faster
c) It promotes decentralization and fair distribution
d) Quantum computers can't mine

<details>
<summary>Answer</summary>
**c) It promotes decentralization and fair distribution**

ASIC-resistant RandomX allows anyone with a CPU to mine competitively. This prevents mining centralization, ensures fair coin distribution, and aligns with "The People's Coin" philosophy.
</details>

---

**Question 6:** What should you NEVER do with your private key?

a) Back it up
b) Encrypt it
c) Share it with anyone (including support/devs)
d) Store it on paper

<details>
<summary>Answer</summary>
**c) Share it with anyone (including support/devs)**

NEVER share your private key with anyone. Legitimate services never need it. Anyone with your private key can steal your coins permanently.
</details>

---

**Question 7:** What does "store now, decrypt later" attack mean?

a) Attackers steal coins now
b) Attackers record encrypted data now, decrypt when quantum computers exist
c) Attackers store coins in wallets
d) Attackers decrypt blockchain data

<details>
<summary>Answer</summary>
**b) Attackers record encrypted data now, decrypt when quantum computers exist**

This threat is already real - adversaries can record blockchain transactions today and decrypt them in 5-10 years when quantum computers arrive, compromising historical transactions. Dilithion prevents this by being quantum-safe from genesis.
</details>

---

## Course Complete! 🎓

**Congratulations! You've mastered:**

✅ **Module 1:** The quantum threat and why it matters
✅ **Module 2:** How post-quantum cryptography works
✅ **Module 3:** Blockchain fundamentals (blocks, transactions, consensus)
✅ **Module 4:** Dilithion's architecture and design
✅ **Module 5:** Mining with RandomX (CPU-friendly PoW)
✅ **Module 6:** Wallet security and best practices
✅ **Module 7:** The future of quantum-safe cryptocurrency

---

## Share Your Achievement!

**You've completed the Dilithion Post-Quantum Cryptocurrency Course!**

Share on social media:
```
🎓 Just completed the Dilithion PQ Cryptocurrency Course!

I now understand:
✅ How quantum computers threaten crypto
✅ Why CRYSTALS-Dilithium is quantum-safe
✅ How Dilithion protects against future attacks

The quantum era is coming. Are you ready?

#Dilithion #PostQuantum #Cryptocurrency #QuantumSafe
```

---

## Continue Learning

### Next Steps:

1. **Run a Dilithion node**
   - Download from GitHub
   - Join the network
   - Mine your first block!

2. **Join the community**
   - Discord: [link]
   - Reddit: r/dilithion
   - Twitter: @DilithionCoin

3. **Read the technical documentation**
   - Whitepaper
   - RPC API docs
   - Mining guide

4. **Contribute**
   - Test the software
   - Report bugs
   - Help others learn
   - Build tools

---

## Resources

### Official Links
- Website: https://dilithion.org
- GitHub: https://github.com/dilithion/dilithion
- Whitepaper: [PDF]
- Discord: [link]

### External Resources
- NIST PQC Project: https://csrc.nist.gov/Projects/post-quantum-cryptography
- CRYSTALS-Dilithium Specification: https://pq-crystals.org/dilithium/
- Quantum Threat Timeline: https://globalriskinstitute.org/quantum-threat/
- RandomX Specification: https://github.com/tevador/RandomX

---

**Thank you for learning with Dilithion!**

*The future is quantum. The solution is Dilithion.*

---

---

# Glossary of Technical Terms

## A

**Address**
A unique identifier (like D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV) derived from a public key, used to receive cryptocurrency. Think of it like a bank account number.

**AES (Advanced Encryption Standard)**
Symmetric encryption standard used to measure security levels. AES-128, AES-192, and AES-256 represent different key sizes.

**Algorithm**
A set of rules or steps for solving a problem. Cryptographic algorithms process data to provide security.

**ASIC (Application-Specific Integrated Circuit)**
Specialized hardware designed for one purpose (like mining Bitcoin). Much faster than general-purpose CPUs but can't do anything else.

## B

**Base58Check**
Encoding method that converts binary data into human-readable text using 58 characters (excludes confusing characters like 0, O, l, I). Used for cryptocurrency addresses.

**BIP (Bitcoin Improvement Proposal)**
Standards for Bitcoin protocol. BIP39 defines mnemonic phrases for wallet recovery.

**Block**
A container of transactions that gets added to the blockchain. Like a page in a ledger book.

**Block Header**
Metadata about a block (timestamp, difficulty, previous block hash, etc.) without the actual transaction data.

**Block Height**
The position of a block in the blockchain. Genesis block is height 0, next is height 1, etc.

**Block Reward**
New coins created and given to miners for successfully mining a block. In Dilithion: starts at 50 DIL, halves every 210,000 blocks.

**Block Time**
Average time between blocks. Bitcoin: 10 minutes, Dilithion: 2 minutes.

**Blockchain**
A chain of blocks linked together by cryptographic hashes. Each block references the previous one, making the chain tamper-proof.

## C

**Coinbase Transaction**
The first transaction in a block, created by the miner, containing the block reward. Not related to Coinbase exchange.

**Cold Storage**
Keeping private keys completely offline (paper wallet, hardware wallet disconnected). Safest for long-term storage.

**Consensus**
Agreement among network participants about the current state of the blockchain. Prevents double-spending.

**CPU (Central Processing Unit)**
The main processor in a computer. RandomX mining is optimized for CPUs.

**CRYSTALS-Dilithium**
Post-quantum digital signature algorithm standardized by NIST (FIPS 204). Based on lattice cryptography, resistant to quantum attacks.

**CRYSTALS-Kyber**
Post-quantum key encapsulation mechanism (for encryption) standardized by NIST. Companion to Dilithium for different cryptographic needs.

**Cryptographic Hash Function**
One-way function that converts input data into a fixed-size output (hash). Cannot be reversed. Examples: SHA-256, SHA-3.

## D

**DAG (Directed Acyclic Graph)**
Alternative to linear blockchain where multiple blocks can be produced in parallel. Used by some cryptocurrencies, not Dilithion.

**DEX (Decentralized Exchange)**
Cryptocurrency exchange without central authority. Trades happen peer-to-peer.

**Difficulty**
How hard it is to find a valid block hash. Adjusts automatically to keep block time consistent.

**Difficulty Adjustment**
Periodic recalculation of mining difficulty. Dilithion: every 2,016 blocks (~2.8 days).

**Digital Signature**
Cryptographic proof that a message was created by the holder of a specific private key. Like a handwritten signature, but unforgeable.

**Discrete Logarithm Problem**
Mathematical problem underlying ECDSA security. Quantum computers can solve this efficiently (Shor's Algorithm).

**Double-Spend**
Attempting to spend the same coins twice. Blockchain consensus prevents this.

## E

**ECDSA (Elliptic Curve Digital Signature Algorithm)**
Signature scheme used by Bitcoin, Ethereum, and most cryptocurrencies. Vulnerable to quantum computers (Shor's Algorithm).

**Encryption**
Converting data into unreadable form without the correct key. Protects confidentiality.

**Entropy**
Randomness. High entropy = unpredictable, secure for cryptographic keys.

## F

**FALCON**
Alternative post-quantum signature scheme (NIST standard). More compact than Dilithium but harder to implement.

**Fee**
Payment to miners for including your transaction in a block. Higher fees = faster confirmation.

**Fee Rate**
Fee per byte of transaction data. Miners prioritize higher fee rates.

**FIPS (Federal Information Processing Standard)**
US government standards for cryptography. FIPS 202 = SHA-3, FIPS 204 = Dilithium.

**Fork**
(1) Code divergence (2) Blockchain split into two chains (temporary or permanent).

**Full Node**
A computer running software that validates all blocks and transactions. Stores complete blockchain copy.

## G

**Genesis Block**
The first block in a blockchain (height 0). Dilithion's genesis: January 1, 2026 00:00:00 UTC.

**GPU (Graphics Processing Unit)**
Processor designed for graphics but also good at parallel computation. Used for mining some cryptocurrencies, not efficient for RandomX.

**Grover's Algorithm**
Quantum algorithm that speeds up search problems (quadratic speedup). Affects hash functions but doesn't break them - only halves security bits.

## H

**Halving**
Periodic reduction of block reward by 50%. Dilithion: every 210,000 blocks (~8 months).

**Hard Fork**
Blockchain upgrade that is NOT backward-compatible. Requires all nodes to update or network splits.

**Hash**
Output of a cryptographic hash function. Fixed-size "fingerprint" of data.

**Hash Function**
See Cryptographic Hash Function.

**Hashrate**
Mining speed measured in hashes per second (H/s). RandomX: ~65 H/s per CPU core.

**Hot Wallet**
Wallet connected to the internet. Convenient but less secure than cold storage.

## I

**Immutable**
Cannot be changed. Blockchain history is immutable due to cryptographic linking.

## K

**Keccak**
The cryptographic sponge function underlying SHA-3. Winner of NIST hash function competition.

**Key Derivation Function (KDF)**
Algorithm that derives cryptographic keys from passwords. Example: PBKDF2.

**Key Pair**
A matched public key and private key used in asymmetric cryptography.

**Keylogger**
Malware that records keystrokes to steal passwords and private keys.

## L

**Lattice Cryptography**
Post-quantum cryptography based on finding short vectors in high-dimensional lattices. Basis for Dilithium and Kyber.

**Layer 2**
Solutions built on top of a blockchain (Layer 1) to improve scalability. Example: Lightning Network for Bitcoin.

**LevelDB**
Fast key-value database used by Dilithion for blockchain storage.

**Lightweight Wallet**
Wallet that doesn't download the full blockchain. Relies on full nodes for data. Also called SPV wallet.

**Locktime**
Earliest time or block height when a transaction can be included in a block.

## M

**Mainnet**
The main blockchain network (as opposed to testnet).

**Mempool**
Temporary storage for unconfirmed transactions waiting to be mined.

**Merkle Root**
A single hash representing all transactions in a block. Efficient way to prove transaction inclusion.

**Mining**
Process of creating new blocks by solving proof-of-work puzzles. Secures network and distributes new coins.

**Mining Pool**
Group of miners combining hashrate to find blocks more frequently, sharing rewards.

**Module-LWE (Module Learning With Errors)**
Lattice problem underlying CRYSTALS-Dilithium security. Believed to be hard even for quantum computers.

**Multisig (Multi-signature)**
Wallet requiring multiple signatures to spend (e.g., 2-of-3). Increased security.

## N

**NIST (National Institute of Standards and Technology)**
US government agency that sets cryptographic standards. Ran 6-year competition to select post-quantum algorithms.

**NIST PQC (Post-Quantum Cryptography)**
NIST project to standardize quantum-resistant algorithms. Selected Dilithium, Kyber, SPHINCS+, and FALCON in 2022.

**Node**
A computer running blockchain software that participates in the network.

**Nonce**
"Number used once." Random value tried during mining to find valid block hash.

**NISQ (Noisy Intermediate-Scale Quantum)**
Current era of quantum computing: 50-1,000 qubits with high error rates. Not yet cryptographically relevant.

## O

**Orphan Block**
Valid block not included in the main chain (another miner's block won).

## P

**P2P (Peer-to-Peer)**
Network architecture where participants communicate directly without central server.

**Paper Wallet**
Private key printed/written on paper for cold storage.

**PBKDF2 (Password-Based Key Derivation Function 2)**
Algorithm to derive encryption keys from passwords. Makes brute-force attacks slower.

**PQ (Post-Quantum)**
Cryptography designed to resist quantum computer attacks.

**Post-Quantum Cryptography**
Algorithms believed to be secure against both classical and quantum computers. Examples: lattice-based, hash-based, code-based.

**Private Key**
Secret number that allows spending cryptocurrency. Must be kept secret. In Dilithion: 4,032 bytes.

**Proof-of-Work (PoW)**
Consensus mechanism requiring computational work to create blocks. Used by Bitcoin and Dilithion.

**Pruning**
Discarding old blockchain data to save disk space while maintaining security.

**Public Key**
Cryptographic key derived from private key, shared publicly. Used to verify signatures and receive funds. In Dilithion: 1,952 bytes.

## Q

**Quantum Computer**
Computer using quantum mechanics (qubits, superposition, entanglement) to solve certain problems exponentially faster than classical computers.

**Quantum Supremacy**
Achievement demonstrated by Google (2019): quantum computer solving problem impractical for classical computers.

**Qubit**
Quantum bit. Unlike classical bits (0 or 1), qubits can be in superposition of both states simultaneously.

## R

**RandomX**
ASIC-resistant, CPU-optimized proof-of-work algorithm. Uses random code execution and memory-hard operations. Originally from Monero.

**Recovery Phrase**
(Mnemonic phrase, seed phrase) 12-24 words that can restore a wallet. Based on BIP39 standard.

**Reorg (Reorganization)**
When a blockchain's recent history changes because a longer chain is discovered.

## S

**Satoshi**
Smallest unit of a cryptocurrency. 1 DIL = 100,000,000 satoshis (like cents in a dollar).

**Script**
Small program that defines spending conditions. Used in transaction outputs.

**Seed**
Random data used to generate a wallet's keys.

**Seed Phrase**
See Recovery Phrase.

**SHA-3 (Secure Hash Algorithm 3)**
Quantum-resistant cryptographic hash function (NIST FIPS 202). Based on Keccak. Dilithion uses SHA-3-256.

**Shor's Algorithm**
Quantum algorithm (1994) that can efficiently factor large numbers and solve discrete logarithm problems. Breaks RSA and ECDSA.

**Signature**
See Digital Signature.

**Soft Fork**
Backward-compatible blockchain upgrade. Old nodes continue working.

**Solo Mining**
Mining alone (not in a pool). Irregular but keeps full block rewards.

**SPV (Simplified Payment Verification)**
Lightweight wallet that verifies transactions without downloading full blockchain.

**SPHINCS+**
Post-quantum signature scheme (NIST standard). Hash-based, very large signatures but conceptually simple.

**Store Now, Decrypt Later**
Attack where adversaries record encrypted data today and decrypt it when quantum computers exist in 5-10 years.

**Superposition**
Quantum property where qubits can be in multiple states simultaneously (both 0 and 1). Key to quantum computer power.

## T

**Testnet**
Separate blockchain for testing. Uses test coins with no real value.

**Throughput**
Number of transactions processed per second (TPS).

**Timestamp**
Time when a block was created (Unix time: seconds since Jan 1, 1970).

**Transaction**
Transfer of value from inputs (previous outputs) to new outputs.

**TXID (Transaction ID)**
Unique identifier for a transaction (hash of transaction data).

## U

**UTXO (Unspent Transaction Output)**
Output from a transaction that hasn't been spent yet. Your balance = sum of UTXOs you control.

**uint256**
256-bit unsigned integer. Used for hashes in Dilithion (32 bytes).

## V

**Vanity Address**
Address with custom prefix (e.g., D1Love...). Requires generating many addresses until desired pattern appears.

**Verification**
Checking that a signature is valid for a given public key and message.

## W

**Wallet**
Software to manage private keys, create transactions, and interact with blockchain. Does NOT store coins (coins exist on blockchain).

**Wallet Encryption**
Protecting wallet file with a password. Encrypts private keys so attackers need password to steal coins.

**Whitepaper**
Technical document describing a cryptocurrency's design, purpose, and implementation.

## Abbreviations

**AES** = Advanced Encryption Standard
**ASIC** = Application-Specific Integrated Circuit
**BIP** = Bitcoin Improvement Proposal
**CPU** = Central Processing Unit
**DAG** = Directed Acyclic Graph
**DEX** = Decentralized Exchange
**ECDSA** = Elliptic Curve Digital Signature Algorithm
**FIPS** = Federal Information Processing Standard
**GPU** = Graphics Processing Unit
**H/s** = Hashes per second
**KDF** = Key Derivation Function
**NIST** = National Institute of Standards and Technology
**NISQ** = Noisy Intermediate-Scale Quantum
**P2P** = Peer-to-Peer
**PBKDF2** = Password-Based Key Derivation Function 2
**PoW** = Proof-of-Work
**PQ** = Post-Quantum
**RPC** = Remote Procedure Call
**SHA** = Secure Hash Algorithm
**SPV** = Simplified Payment Verification
**TPS** = Transactions Per Second
**TXID** = Transaction ID
**UTXO** = Unspent Transaction Output

---

**Course Version:** 1.0
**Last Updated:** January 1, 2026
**License:** Creative Commons Attribution 4.0

Feel free to share this course with anyone interested in post-quantum cryptocurrency!
