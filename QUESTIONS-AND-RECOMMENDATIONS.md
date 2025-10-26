# Dilithion Questions & Recommendations

**Date:** October 25, 2025
**Status:** Pre-Launch Analysis

---

## Question 1: Block Time Change (2 min → 4 min)

### Current: 120 seconds (2 minutes)
### Proposed: 240 seconds (4 minutes)
### Bitcoin: 600 seconds (10 minutes)

### Impact Analysis

#### ✅ ADVANTAGES of Changing to 4 Minutes:

**1. Reduced Orphan Rate**
- **Current (2 min):** Higher chance of orphan blocks
- **With 4 min:** ~50% reduction in orphan rate
- **Why:** More time for blocks to propagate across network
- **Benefit:** Less wasted mining work, more stable blockchain

**2. Better for Large Transactions**
- **Dilithium signatures:** 3,309 bytes each
- **Block propagation:** Takes time for large blocks
- **With 4 min:** Network has more time to propagate
- **Benefit:** More reliable confirmation

**3. More Conservative Confirmations**
- **2 min × 6 confirmations:** 12 minutes
- **4 min × 3 confirmations:** 12 minutes (same security, fewer blocks)
- **Benefit:** Simpler for users ("wait for 3 confirmations")

**4. Lower Blockchain Growth Rate**
- **2 min blocks:** 720 blocks/day
- **4 min blocks:** 360 blocks/day (50% reduction)
- **With large signatures:** Significant storage savings
- **Benefit:** Easier to run full nodes

**5. More Aligned with Network Realities**
- **RandomX mining:** CPU-intensive, takes time to propagate
- **Post-quantum signatures:** Larger than classical signatures
- **Global network:** 4 minutes gives better global reach
- **Benefit:** More inclusive for miners worldwide

#### ⚠️ DISADVANTAGES of 4 Minutes:

**1. Slower Confirmations**
- **Transaction finality:** Takes twice as long
- **User experience:** 4 min wait vs 2 min for first confirmation
- **Exchange deposits:** May require more time

**2. Lower Transaction Throughput (Theoretical)**
- **2 min:** Could fit more transactions per hour
- **4 min:** Half the number of blocks
- **Note:** With current transaction volume, not an issue

#### 💡 RECOMMENDATION: **CHANGE TO 4 MINUTES**

**Rationale:**
1. Better suited for post-quantum signature sizes
2. Significantly reduces orphan rate
3. More sustainable blockchain growth
4. Still 2.5x faster than Bitcoin
5. Better global network participation

**Implementation:**
```cpp
// src/consensus/pow.h
static const int64_t BLOCK_TARGET_SPACING = 240;  // Changed from 120 to 240 seconds
```

**Migration:**
- ✅ Can be changed before mainnet launch
- ✅ Simple one-line change
- ✅ No impact on existing code
- ✅ Difficulty adjustment algorithm handles it automatically

**Comparison:**
| Coin | Block Time | Why |
|------|------------|-----|
| Bitcoin | 10 min | Conservative, global propagation |
| Litecoin | 2.5 min | 4x faster than Bitcoin |
| **Dilithion (proposed)** | **4 min** | **2.5x faster than Bitcoin, suited for PQC** |
| Ethereum | 12-14 sec | Different architecture (PoS) |

---

## Question 2: Preventing Loss of Coins

### Current Risk: **HIGH** (Same as Bitcoin)

**Problem:** If user loses wallet file or forgets password → **Coins lost forever**

### Solutions to Implement:

#### 🔒 Solution 1: HD Wallet with Seed Phrase (RECOMMENDED)

**What is HD Wallet?**
- Hierarchical Deterministic wallet (BIP32/BIP39)
- All keys derived from single seed phrase
- 12 or 24 word mnemonic (e.g., "army van defense...")

**Benefits:**
- ✅ User writes down 12 words → can recover entire wallet
- ✅ No need to backup wallet file
- ✅ Can generate unlimited addresses from seed
- ✅ Industry standard (all major wallets use this)

**Challenge with Dilithium:**
- ⚠️ Dilithium is **randomized** signature scheme
- ⚠️ Cannot use traditional BIP32 key derivation
- ✅ **Solution:** Use seed phrase to derive master key, then generate Dilithium keys deterministically using SHAKE-256

**Implementation:**
```cpp
// Simplified approach:
1. User generates 24-word seed phrase
2. Seed phrase → PBKDF2-SHA3 → Master Seed (32 bytes)
3. For key N: SHAKE-256(MasterSeed || N) → Dilithium key
4. User writes down 24 words → can recover all keys
```

**Estimated Time:** 20-24 hours
**Priority:** HIGH (post-launch month 1)
**Impact:** Massive reduction in coin loss

---

#### 💾 Solution 2: Encrypted Cloud Backup

**Implementation:**
```cpp
// Auto-backup encrypted wallet to cloud
1. Wallet encrypted with user password
2. Upload encrypted wallet to:
   - User's Google Drive
   - User's Dropbox
   - User's iCloud
3. User only needs to remember password
```

**Benefits:**
- ✅ User can't lose wallet file (cloud backup)
- ✅ Still secure (encrypted)
- ✅ Works across devices

**Estimated Time:** 12-16 hours
**Priority:** MEDIUM

---

#### 📱 Solution 3: Social Recovery

**Implementation:**
```cpp
// Split wallet recovery among trusted contacts
1. User designates 5 trusted contacts
2. Wallet encrypted and split into 5 shares
3. Any 3 of 5 shares can recover wallet
4. Uses Shamir's Secret Sharing
```

**Benefits:**
- ✅ Can't lose wallet unless lose contact with 3+ friends
- ✅ No single point of failure
- ✅ Secure (need 3 of 5 shares)

**Estimated Time:** 16-20 hours
**Priority:** MEDIUM (innovative feature)

---

#### 🔔 Solution 4: Wallet Health Monitoring

**Implementation:**
```cpp
// Alert users to backup
1. Detect if wallet not backed up in 30 days
2. Send email/notification reminder
3. Warn if wallet has significant balance but no backup
4. Guide user through backup process
```

**Estimated Time:** 4-6 hours
**Priority:** HIGH (easy win)

---

### RECOMMENDATION: Implement in This Order

**Phase 1 (Month 1): 24-word Seed Phrase Recovery** ⭐⭐⭐
- Most important feature
- Industry standard
- Users expect this
- Biggest impact on coin loss

**Phase 2 (Month 2): Wallet Health Monitoring**
- Quick to implement
- Prevents forgetfulness
- Complements seed phrase

**Phase 3 (Month 3): Cloud Backup Option**
- Extra convenience
- Optional feature
- Appeals to non-technical users

**Phase 4 (Month 6+): Social Recovery**
- Advanced feature
- Differentiator
- Marketing value

---

## Question 3: What Type of Wallet Will Work?

### Current State: **Command-Line Wallet Only**

**What exists now:**
```bash
# Built-in wallet (part of dilithion-node)
./dilithion-node                    # Runs node + wallet
./dilithion-cli getnewaddress       # Get new address
./dilithion-cli getbalance          # Check balance
./dilithion-cli sendtoaddress ...   # Send coins
```

**Type:** Full node wallet (like Bitcoin Core)

---

### Wallet Types Needed:

#### 1. ✅ **Full Node Wallet** (EXISTS)

**Current Implementation:**
- Runs full blockchain node
- Stores entire blockchain
- Maximum security
- Maximum privacy

**Who uses:**
- Miners
- Power users
- Exchanges
- Developers

**Status:** ✅ Complete and working

---

#### 2. 📱 **Mobile Wallet** (NEEDED)

**What's needed:**
- iOS app
- Android app
- Lightweight (SPV-style)
- QR code scanning
- Push notifications

**Technologies:**
- React Native (cross-platform)
- Or Flutter
- Connect to full nodes via RPC
- Simplified Payment Verification (SPV)

**Estimated Time:** 160-240 hours (2-3 months full-time)
**Priority:** HIGH (Month 2-3)

**Features:**
```
- Send/receive coins
- QR code scanner
- Transaction history
- Price tracking
- Push notifications for receives
- Touch ID / Face ID
- Backup seed phrase
```

---

#### 3. 💻 **Desktop GUI Wallet** (NEEDED)

**What's needed:**
- Windows app
- Mac app
- Linux app
- User-friendly interface

**Technologies:**
- Electron (cross-platform)
- Or Qt framework
- Wraps dilithion-node

**Estimated Time:** 80-120 hours
**Priority:** HIGH (Month 1-2)

**Features:**
```
- Visual transaction history
- Address book
- One-click mining start/stop
- Wallet encryption UI
- Backup/restore wizard
- Network status
```

---

#### 4. 🌐 **Web Wallet** (OPTIONAL)

**What's needed:**
- Browser-based wallet
- Hosted service
- Keys stored encrypted on server

**WARNING:** ⚠️ Users don't control private keys
- Less secure
- Requires trust
- Similar to exchange wallet

**Priority:** LOW (controversial, security concerns)

---

#### 5. 🧊 **Hardware Wallet** (FUTURE)

**What's needed:**
- Ledger support
- Trezor support
- Custom post-quantum hardware wallet

**Challenge:**
- Dilithium keys are large (4KB secret key)
- May not fit in existing hardware wallet memory
- Needs custom firmware

**Priority:** LOW (long-term, requires hardware partnership)

---

### RECOMMENDATION: Development Priority

**Month 1:**
- ✅ Command-line wallet (EXISTS)
- Start desktop GUI wallet

**Month 2:**
- Complete desktop GUI wallet
- Start mobile wallet development

**Month 3:**
- Complete mobile wallet (iOS + Android)
- Beta testing

**Month 6+:**
- Hardware wallet research
- Advanced features

---

## Question 4: Launch Website Design

### Website Requirements:

I'll create a complete website specification in a separate document. Here's the overview:

**Features Needed:**
1. **Countdown Timer** to mainnet launch
2. **Live Dashboard** showing:
   - Current block height
   - Network hash rate
   - Active miners
   - Total supply
   - Current block reward
   - Difficulty
3. **Getting Started Guide**
4. **Download Links** (wallet, miner)
5. **Documentation** links
6. **Community** links (Discord, Telegram, Reddit)

**I'll create full website design next...**

---

## Question 5: Mobile Mining - Is it Practical?

### Quick Answer: **❌ NOT PRACTICAL (But Possible)**

### Analysis:

#### Technical Feasibility: ✅ POSSIBLE

**RandomX Requirements:**
- CPU: Any modern processor
- RAM: 2GB minimum for RandomX cache
- Dilithium: CPU can handle signing

**Modern Phones:**
- iPhone 15: 6GB RAM, A17 chip
- Android flagships: 8-12GB RAM
- **Verdict:** Technically possible

---

#### Performance Reality: ⚠️ VERY SLOW

**Expected Hash Rates:**

| Device | Hash Rate | vs Desktop |
|--------|-----------|------------|
| Desktop (Ryzen 9) | 660 H/s (10 cores) | Baseline |
| Desktop (Single core) | 66 H/s | 1x |
| **iPhone 15** | ~10-20 H/s | **0.15-0.30x** |
| **Android Phone** | ~8-15 H/s | **0.12-0.23x** |

**Mining Economics:**
```
Desktop: 660 H/s = Good chance to mine blocks
Phone:   15 H/s  = Would take 44x longer
                  = Practically useless for competitive mining
```

---

#### Battery & Heat Problems: ❌ MAJOR ISSUES

**1. Battery Drain**
- RandomX is CPU-intensive
- Would drain phone battery in 1-2 hours
- Phone unusable while mining

**2. Overheating**
- CPU at 100% → phone overheats
- Thermal throttling → hash rate drops
- Risk of hardware damage

**3. Data Usage**
- Need to sync blockchain (or connect to pool)
- Hundreds of MB to GB of data
- Expensive on mobile data plans

**4. User Experience**
- Phone slows to crawl
- Apps lag
- Calls might drop
- Terrible UX

---

#### Economic Reality: ❌ NOT PROFITABLE

**Electricity Cost:**
```
Phone mining 24/7:
- Power draw: ~5W (while mining)
- Daily cost: $0.01-0.02
- Monthly: $0.30-0.60

Expected earnings:
- At 15 H/s: Negligible
- Worse than buying coins directly
```

**Phone Degradation:**
- Battery health decreases rapidly
- Reduced phone lifespan
- Cost >> Any mining rewards

---

### ✅ ALTERNATIVE: "Educational Mining Mode"

**Better Approach:**
```
Instead of competitive mining, offer:

1. "Learn to Mine" Mode
   - Mine for 5 minutes to see how it works
   - Educational, not for profit
   - Shows mining process
   - Earns tiny amount (lottery ticket)

2. Pool Monitoring App
   - Monitor desktop mining from phone
   - Real-time stats
   - Notifications when you mine a block
   - Remote control (start/stop desktop miner)

3. Faucet Integration
   - Claim small amounts for free
   - Learn how to use wallet
   - Get started without mining
```

---

### RECOMMENDATION: **DO NOT Promote Phone Mining**

**Instead:**
1. ✅ Make desktop mining easy
2. ✅ Create mobile **wallet** app (not miner)
3. ✅ Add "educational mining demo" to mobile app
4. ✅ Warn users: "Phone mining not profitable"
5. ✅ Offer monitoring app for desktop miners

**Marketing Message:**
> "Dilithion is CPU-mineable, but designed for desktop/laptop CPUs. Use your phone to manage your wallet and monitor your desktop mining operation."

---

## Question 6: Re-run Wallet Persistence Tests

I'll run the tests again now...

---

## Summary of Recommendations

### 1. Block Time: ✅ **CHANGE TO 4 MINUTES**
- Better for post-quantum signatures
- Reduced orphan rate
- More sustainable
- Still 2.5x faster than Bitcoin

### 2. Prevent Coin Loss: ✅ **IMPLEMENT HD WALLET** (Priority #1)
- 24-word seed phrase recovery
- Industry standard
- Month 1 post-launch
- Biggest impact on user confidence

### 3. Wallet Types: ✅ **BUILD GUI + MOBILE**
- Desktop GUI wallet (Month 1-2)
- Mobile wallet (Month 2-3)
- Command-line exists already

### 4. Website: ✅ **CREATE LAUNCH WEBSITE** (I'll design next)
- Countdown timer
- Live dashboard
- Getting started guide
- Download links

### 5. Phone Mining: ❌ **DO NOT PROMOTE**
- Not practical
- Battery/heat issues
- Not profitable
- Offer monitoring app instead

---

**Next Steps:**
1. Re-run wallet persistence tests
2. Design launch website
3. Create HD wallet implementation plan
4. Design desktop GUI wallet mockup

Let me know which you'd like me to work on first!
