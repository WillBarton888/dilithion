# Day 7: Dilithion Comprehensive Final Exam

**Date:** October 26, 2025
**Duration:** ~3-4 hours total
**Passing Score:** 25/30 points
**Instructions:** Work through each section independently. Write your answers in this document or on paper.

---

## Part 1: Comprehensive Written Exam (90 minutes)

**Instructions:** Answer all questions in your own words. No copying from documentation.

---

### Section A: Post-Quantum Cryptography (Questions 1-10)

**1.** In your own words, why will quantum computers break Bitcoin's signatures?

**Answer:**

---

**2.** What is CRYSTALS-Dilithium3, and why did we choose it?

**Answer:**

---

**3.** How large are Dilithium3 signatures compared to Bitcoin's ECDSA signatures?

**Answer:**

---

**4.** What does "Module-LWE" stand for, and what security does it provide?

**Answer:**

---

**5.** Why do we use SHA-3 instead of SHA-256?

**Answer:**

---

**6.** What are the three sizes we care about in Dilithium3?
- Public key: ___ bytes
- Private key: ___ bytes
- Signature: ___ bytes

---

**7.** True or False: Quantum computers can break all cryptography.

**Answer:**

**Explanation:**

---

**8.** What is the "harvest now, decrypt later" threat?

**Answer:**

---

**9.** What year did NIST standardize Dilithium as FIPS 204?

**Answer:**

---

**10.** Name one other NIST post-quantum standard besides Dilithium.

**Answer:**

---

### Section B: Blockchain Architecture (Questions 11-20)

**11.** What is the UTXO model in your own words?

**Answer:**

---

**12.** What are the four key pieces of data in a block header?

1. ___________________
2. ___________________
3. ___________________
4. ___________________

---

**13.** What is a Merkle root, and why is it important?

**Answer:**

---

**14.** How does the blockchain achieve immutability?

**Answer:**

---

**15.** What is the mempool, and what does it do?

**Answer:**

---

**16.** How are transactions prioritized in the mempool?

**Answer:**

---

**17.** What is a "double-spend attack"?

**Answer:**

---

**18.** What happens when two miners find a block at the same time?

**Answer:**

---

**19.** What is the "longest chain rule"?

**Answer:**

---

**20.** True or False: Once a block is added to the blockchain, it can never be changed.

**Answer:**

**Explanation:**

---

### Section C: Mining & Consensus (Questions 21-30)

**21.** What is Dilithion's block time, and why is it 4 minutes instead of 10?

**Answer:**

---

**22.** What is the initial block reward?

**Answer:**

---

**23.** How often does the block reward halve?

**Answer:**

---

**24.** What is the maximum supply of Dilithion?

**Answer:**

---

**25.** What is RandomX, and why do we use it?

**Answer:**

---

**26.** Approximately how many hashes per second can one CPU core produce?

**Answer:**

---

**27.** How often does difficulty adjust, and why?

**Answer:**

---

**28.** What is a "51% attack"?

**Answer:**

---

**29.** If the network hashrate doubles, what happens to difficulty?

**Answer:**

---

**30.** True or False: Mining rewards are the only way new DIL is created.

**Answer:**

**Explanation:**

---

### Section D: Network & P2P (Questions 31-40)

**31.** What port does Dilithion use for mainnet?

**Answer:**

---

**32.** What is the network magic number for mainnet?

**Answer:**

---

**33.** How do nodes discover peers?

**Answer:**

---

**34.** What is the VERSION/VERACK handshake?

**Answer:**

---

**35.** What message type is used to announce a new block?

**Answer:**

---

**36.** What is "headers-first" synchronization?

**Answer:**

---

**37.** Name two DoS protections built into the network protocol.

1. ___________________
2. ___________________

---

**38.** What happens if a peer sends you an invalid block?

**Answer:**

---

**39.** What is an "eclipse attack"?

**Answer:**

---

**40.** What is the maximum message size allowed in the protocol?

**Answer:**

---

### Section E: Security & Responsibilities (Questions 41-50)

**41.** What is the #1 rule about private keys?

**Answer:**

---

**42.** How are private keys encrypted in the wallet.dat file?

**Answer:**

---

**43.** What is PBKDF2, and why do we use 100,000 iterations?

**Answer:**

---

**44.** What should you do if someone reports a critical security vulnerability?

**Answer:**

---

**45.** What are the four severity levels in the incident response plan?

1. ___________________
2. ___________________
3. ___________________
4. ___________________

---

**46.** What should you do if private keys are discovered to be exposed?

**Answer:**

---

**47.** Should you ever roll back the blockchain? When?

**Answer:**

---

**48.** What is "responsible disclosure"?

**Answer:**

---

**49.** What are the three key disclaimers you must always include?

1. ___________________
2. ___________________
3. ___________________

---

**50.** True or False: As the developer, you are legally liable if someone loses money using Dilithion.

**Answer:**

**Explanation:**

---

## Part 2: Code Explanation Challenge (60 minutes)

**Instructions:** Explain what each code snippet does in **plain English** as if teaching someone who doesn't know C++.

---

### Code Snippet 1: Key Generation

```cpp
bool GenerateKeyPair(CKey& key) {
    key.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
    key.vchPrivKey.resize(DILITHIUM_SECRETKEY_SIZE);

    int result = pqcrystals_dilithium3_ref_keypair(
        key.vchPubKey.data(),
        key.vchPrivKey.data()
    );

    return result == 0;
}
```

**Your explanation:**

---

### Code Snippet 2: Transaction Validation

```cpp
for (const auto& txin : tx.vin) {
    if (!view.HaveCoins(txin.prevout)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missing");
    }

    const Coin& coin = view.AccessCoin(txin.prevout);
    if (!VerifySignature(coin.pubkey, tx.GetHash(), txin.signature)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-signature");
    }
}
```

**Your explanation:**

---

### Code Snippet 3: Mining Loop

```cpp
while (true) {
    pblock->nNonce++;

    uint256 hash = RandomXHash(pblock->GetBlockHeader());

    if (hash < target) {
        // Found a valid block!
        return pblock;
    }

    if (pblock->nNonce % 1000 == 0) {
        // Check if we should stop mining
        if (ShutdownRequested()) break;
    }
}
```

**Your explanation:**

---

### Code Snippet 4: Fee Calculation

```cpp
Amount CalculateFee(const CTransaction& tx) {
    Amount nValueIn = 0;
    for (const auto& txin : tx.vin) {
        nValueIn += txin.prevout.nValue;
    }

    Amount nValueOut = 0;
    for (const auto& txout : tx.vout) {
        nValueOut += txout.nValue;
    }

    return nValueIn - nValueOut;
}
```

**Your explanation:**

---

### Code Snippet 5: Secure Memory Wiping

```cpp
CKeyingMaterial::~CKeyingMaterial() {
    if (!data.empty()) {
        memset(data.data(), 0, data.size());
    }
}
```

**Your explanation:**

---

## Part 3: Real-World Troubleshooting (30 minutes)

**Instructions:** For each scenario, explain what's likely wrong and how to fix it.

---

### Scenario 1: Port Binding Error

**User reports:**
```
ERROR: Cannot bind to port 8444 (Address already in use)
```

**What's wrong?**

**How to fix it?**

---

### Scenario 2: Mining But Not Finding Blocks

**User reports:**
```
I've been mining for 3 hours on 4 CPU cores but haven't found a block.
My hashrate shows 260 H/s.
```

**What's wrong?**

**How to explain this to the user?**

---

### Scenario 3: Transaction Not Confirming

**User reports:**
```
I sent a transaction 2 hours ago but it still shows 0 confirmations.
Transaction fee was 0.0001 DIL.
```

**What might be wrong?**

**How to troubleshoot?**

---

### Scenario 4: Wallet Balance Shows Zero

**User reports:**
```
I had 50 DIL in my wallet. I closed dilithion-node and reopened it.
Now it shows 0 DIL balance. My wallet.dat file is still there.
```

**What's wrong?**

**How to fix it?**

---

### Scenario 5: Suspected Attack

**User reports:**
```
The last 10 blocks were all mined by the same address.
Is this a 51% attack?
```

**What's happening?**

**How to respond?**

---

## Part 4: Readiness Assessment (30 minutes)

---

### A. Technical Knowledge Self-Rating

Rate yourself honestly on each topic (1-10 scale):

**1 = No understanding | 5 = Basic grasp | 10 = Could teach it**

| Topic | Your Rating (1-10) |
|-------|-------------------|
| Post-quantum cryptography fundamentals | ___ |
| Blockchain architecture (UTXO, blocks, consensus) | ___ |
| Wallet security and encryption | ___ |
| Mining and proof-of-work | ___ |
| Network protocol and P2P | ___ |

**Your average technical knowledge score:** ___/10

---

### B. Practical Skills Checklist

Check YES only if you can confidently do this RIGHT NOW without help:

- [ ] **YES / NO** - Compile Dilithion from source
- [ ] **YES / NO** - Generate a genesis block
- [ ] **YES / NO** - Start a node and begin mining
- [ ] **YES / NO** - Create a wallet and receive DIL
- [ ] **YES / NO** - Send a transaction via RPC
- [ ] **YES / NO** - Explain to a user why their transaction isn't confirming
- [ ] **YES / NO** - Respond appropriately to a security vulnerability report

**Count your YES answers:** ___/7

**Practical skills score:** (YES count) × (10/7) = ___/10

---

### C. Responsibility Check

Mark TRUE or FALSE for each statement:

- [ ] **TRUE / FALSE** - I understand this is experimental software
- [ ] **TRUE / FALSE** - I will always disclose AI-assisted development
- [ ] **TRUE / FALSE** - I will respond to critical bugs within 1 hour
- [ ] **TRUE / FALSE** - I will never claim Dilithion is "guaranteed safe"
- [ ] **TRUE / FALSE** - I am prepared to delay launch if critical issues are found
- [ ] **TRUE / FALSE** - I will give credit to security researchers
- [ ] **TRUE / FALSE** - Users' funds are ultimately their own responsibility, but I'll do my best

**Count your TRUE answers:** ___/7

**Responsibility score:** (TRUE count) × (10/7) = ___/10

---

## Final Readiness Score

```
Technical Knowledge Average:    ___/10
Practical Skills Score:         ___/10
Responsibility Check:           ___/10
─────────────────────────────────────
TOTAL READINESS SCORE:          ___/30
```

---

## Score Interpretation

### 25-30 points: READY TO PROCEED ✅

**You are ready for Week 2 (Going Public)!**

You have solid understanding of the technology, practical skills to operate the software, and the right mindset for responsible experimental launch.

**Next step:** Begin WEEK-2-ACTION-PLAN.md on November 3, 2025

**Recommendation:** Review any topics where you scored below 7/10 before going public.

---

### 20-24 points: PROCEED WITH CAUTION ⚠️

**You have foundational knowledge but some gaps remain.**

**Before proceeding to Week 2:**
1. Identify your lowest-scoring areas
2. Re-read those sections from Days 1-7
3. Practice the practical skills you marked NO
4. Retake this assessment

**Recommendation:** Take 2-3 extra days to strengthen weak areas, then retake exam.

---

### 15-19 points: NOT READY YET ❌

**Significant knowledge gaps exist that could cause problems during launch.**

**Before proceeding:**
1. Re-study Days 1-7 materials thoroughly
2. Read through the actual code files again
3. Practice running the node, mining, creating transactions
4. Work through POST-QUANTUM-CRYPTO-COURSE.md modules with quizzes

**Recommendation:** Take 1-2 weeks additional study, then retake exam. Do NOT go public until you score 25+.

---

### Below 15 points: DO NOT LAUNCH 🛑

**Fundamental gaps in understanding exist.**

**Honest assessment:** You may not be ready to launch a cryptocurrency yet. This isn't a failure - it's responsible self-awareness.

**Options:**
1. **Extended study:** Take 1-2 months to deeply learn blockchain technology
2. **Find a co-developer:** Partner with someone who has blockchain experience
3. **Research project only:** Open-source the code as a learning project, not a live currency
4. **Delay indefinitely:** Wait until you're truly ready

**Remember:** Launching before you're ready puts users at risk. There's no shame in waiting.

---

## Knowledge Gap Identification

If you scored below 25/30, use this section to identify weak areas:

### Topics I need to review:
- [ ] Post-quantum cryptography (Dilithium3, SHA-3)
- [ ] UTXO model and transaction structure
- [ ] Block structure and Merkle trees
- [ ] Wallet encryption and key management
- [ ] Mining and difficulty adjustment
- [ ] Network protocol and peer discovery
- [ ] Security incidents and response procedures
- [ ] Code compilation and practical operation

### Practical skills I need to practice:
- [ ] Compiling from source
- [ ] Running a node
- [ ] Mining blocks
- [ ] Creating transactions
- [ ] Using RPC commands
- [ ] Troubleshooting common issues

### Study plan to improve:
(Write your plan here)

---

## After Completing This Exam

### If you scored 25-30:
1. Save this completed exam for your records
2. Review the WEEK-2-ACTION-PLAN.md
3. Prepare to go public on November 3, 2025
4. Get excited - you're ready! 🚀

### If you scored 20-24:
1. Identify weak areas above
2. Re-study those specific topics
3. Retake the exam in 2-3 days
4. Don't rush - better to delay than fail publicly

### If you scored below 20:
1. Have an honest conversation with yourself about readiness
2. Consider the options listed in your score interpretation
3. There's no shame in delaying or finding help
4. Responsible decision-making is a sign of maturity

---

## Resources for Further Study

If you need to review any topics:

**Main documentation:**
- `DILITHION-TRAINING-SUMMARY.md` - Master reference guide
- `POST-QUANTUM-CRYPTO-COURSE.md` - Educational modules with quizzes
- `SECURITY-REVIEW-CHECKLIST.md` - Security verification checklist
- `INCIDENT-RESPONSE-PLAN.md` - Emergency procedures

**Code files to re-read:**
- `src/wallet/wallet.cpp` - Key generation, signing, verification
- `src/primitives/transaction.h` - Transaction structure
- `src/primitives/block.h` - Block structure
- `src/consensus/pow.h` - Proof-of-work and consensus
- `src/net/protocol.h` - Network protocol definitions

**External resources:**
- NIST FIPS 204 (Dilithium standard)
- NIST FIPS 202 (SHA-3 standard)
- Bitcoin developer documentation (UTXO model)
- Monero documentation (RandomX)

---

## Good Luck! 🎯

Take your time with this exam. There's no time limit beyond the suggested durations. The goal is honest self-assessment, not racing to finish.

Your future users are counting on you to be ready. Be honest with yourself.

**Last updated:** October 26, 2025
