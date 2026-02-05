# Dilithion Improvement Proposal: VDF Fair Mining

**Status:** Draft for Community Discussion
**Author:** Will
**Date:** February 2026
**Version:** 2 (Updated based on community feedback)

---

## Summary

Replace Dilithion's current RandomX proof-of-work mining with a **VDF-based fair mining system**. This change would:

- Eliminate hashrate advantages (no more "biggest farm wins")
- Reduce energy consumption by ~95%
- Create truly fair block distribution
- Simplify the codebase (remove DFMP complexity)

---

## The Problem

Current mining has fundamental issues:

1. **Hashrate = Power**: A miner with 10x more CPUs gets ~10x more blocks
2. **Energy Waste**: Miners race 24/7, burning electricity. Most hashes are thrown away.
3. **Concentration**: Top 3 addresses have mined 83% of recent blocks
4. **Complexity**: DFMP has 6+ penalty systems trying to enforce fairness

No amount of penalty tuning fixes the core issue: **proof-of-work rewards those who burn the most electricity**.

---

## The Solution: VDF Fair Mining

### What is a VDF?

A **Verifiable Delay Function** is a computation that:
- Takes a fixed amount of time (e.g., 200 seconds)
- Cannot be parallelized — 1 CPU or 1000 CPUs, same time
- Produces a provable result anyone can verify quickly

### How It Works

```
Every ~4 minutes:
1. All miners compute ONE VDF tied to their address
2. The lowest VDF output wins the block
3. Winner sits out for N blocks (cooldown)
4. Repeat
```

### Why This is Fair

| Scenario | Current PoW | VDF Fair Mining |
|----------|-------------|-----------------|
| 1 miner, 1 CPU | 1 ticket | 1 ticket |
| 1 miner, 100 CPUs | 100 tickets | 1 ticket |
| 10 miners, 1 CPU each | 10 tickets total | 10 tickets total |

**Hashrate becomes irrelevant.** Each address gets exactly one ticket per round. More hardware doesn't help.

### The Cooldown

After winning a block, you're excluded from the next N blocks:

| Network Size | Cooldown | Max Share |
|--------------|----------|-----------|
| 10 miners | 10 blocks | 10% |
| 50 miners | 50 blocks | 2% |
| 100+ miners | 100 blocks | 1% |

This **single mechanism** replaces all of DFMP's penalty systems.

---

## Sybil Resistance

The main attack vector is address multiplication — creating many addresses to get many tickets. We address this with layered defenses:

### 1. Address Activation Delay (100 blocks)

New addresses must wait 100 blocks (~7 hours) before their VDF submissions are valid. This prevents reactive address spinning and requires attackers to plan ahead.

### 2. Aggressive Cooldown

With 100-block cooldown, each address can only win ~3 blocks per 360-block window. To capture 50% of blocks (180 per window), an attacker would need:

- **60+ addresses** (180 ÷ 3 per address)
- **60+ dedicated CPU threads** running VDF computations 24/7
- Sustained hardware commitment, not burst rental

### 3. The Economics

| Attack Scale | Addresses Needed | Dedicated Threads | Hardware Cost |
|--------------|------------------|-------------------|---------------|
| 10% of blocks | 12 | 12 | 1 decent server |
| 25% of blocks | 30 | 30 | 2-3 servers |
| 50% of blocks | 60 | 60 | 4-5 servers or dedicated rack |

Compare to current PoW: rent hashrate for an hour, dominate, leave. VDF requires **ongoing, dedicated hardware** — a fundamentally different cost structure.

---

## VDF Security

### Why chiavdf?

We use [chiavdf](https://github.com/Chia-Network/chiavdf), the same VDF library powering Chia Network since 2021.

**Class groups of unknown order** were chosen because:
- No known ASIC/FPGA acceleration exists
- Harder to optimize than RSA or elliptic curves
- Believed to be post-quantum resistant
- Battle-tested in production for 4+ years

### Hardware Acceleration Risk

**Worst case:** Someone builds a 2-5x faster VDF implementation.

This doesn't break the system — faster computation doesn't guarantee a lower output (it's deterministic, not a race). It just lets that entity run more addresses, which brings us back to Sybil costs.

**Mitigation:** VDF iteration count is a consensus parameter. If acceleration emerges, we increase iterations to maintain target duration.

### Long-term Resilience

- Monitor academic VDF research (active area with Ethereum Foundation, Chia funding)
- Class group security is well-studied
- Upgrade path exists if new constructions prove stronger

---

## Benefits

### For Small Miners
- Your single CPU has the same chance as someone with 100 CPUs
- No need to race or optimize — just compute your VDF and wait
- Predictable: if you're not in cooldown, you have a fair shot

### For the Network
- **95% less energy** — no more hash racing
- **Simpler code** — ~500 lines vs ~3000 lines for DFMP
- **Truly decentralized** — no hashrate advantage to accumulate

### For the Environment
- Current: 50 miners × 100% CPU × 24/7 = constant burning
- VDF: 50 miners × 1 thread × 200 seconds per round = minimal usage

---

## Technical Details

### Block Changes

New block header (version 4+) includes:
- `vdfOutput` (32 bytes) — the VDF result
- `vdfProofHash` (32 bytes) — commitment to the proof

Full VDF proof (~100 bytes) stored in coinbase OP_RETURN.

### Identity

Your mining identity becomes your **coinbase address**. No more MIK registration, no more Dilithium signatures, no more identity management.

### Challenge Derivation

Each round's challenge is deterministic and unpredictable:
```
challenge = SHA3-256(previous_block_hash || height)
vdf_input = SHA3-256(challenge || miner_address)
```

This prevents grinding — you can't influence your VDF output without changing the previous block.

---

## Migration Plan

### Phase 1: Development & Testnet (4-6 weeks)

- Integrate chiavdf library
- Implement VDF mining controller
- Deploy on testnet
- Community testing and validation

### Phase 2: Mainnet Hybrid Period (2 weeks)

- Hard fork at announced height (~block 10,000)
- **Both RandomX and VDF blocks accepted**
- Miners upgrade at their own pace
- Safety net: if VDF has issues, RandomX still works

### Phase 3: Mainnet VDF-Only

- Second hard fork at announced height (~block 15,000)
- **Only VDF blocks accepted**
- RandomX mining disabled
- DFMP code deprecated

### Timeline Summary

| Milestone | Estimated Block | Timeframe |
|-----------|-----------------|-----------|
| Testnet activation | N/A | Week 5 |
| Mainnet hybrid start | ~10,000 | Week 9 |
| Mainnet VDF-only | ~15,000 | Week 11 |

Block heights will be announced well in advance with clear upgrade instructions.

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Address multiplication (Sybil) | 100-block activation delay + aggressive cooldown |
| VDF hardware acceleration | Class groups resist optimization; iteration count adjustable |
| Clock synchronization | Epoch-based challenges with 30-second tolerance |
| Low initial participation | Adaptive cooldown scales with miner count |
| Migration confusion | Long hybrid period, clear documentation, testnet first |

---

## What This Means for Current Miners

- **Your hardware still works** — VDF runs on standard CPUs
- **No advantage from more CPUs** — one thread per identity is all you need
- **Simpler setup** — no MIK management, just set your address and mine
- **Fair participation** — equal opportunity, not hashrate wars
- **Lower costs** — no need to run CPUs at 100% constantly

---

## Questions for Discussion

1. **Is this direction right?** Should Dilithion move away from traditional PoW?

2. **Activation delay?** Is 100 blocks enough friction for new addresses?

3. **Cooldown parameters?** Is 10-100 blocks the right range?

4. **VDF duration?** 200 seconds feels right for 4-minute blocks. Thoughts?

5. **Migration timeline?** Too fast? Too slow?

6. **Concerns?** What attack vectors are we missing?

---

## Next Steps

1. **Gather feedback** from community (this document)
2. **Refine parameters** based on input
3. **Implement on testnet** for validation
4. **Migrate mainnet** with hybrid period

---

## References

- [chiavdf GitHub](https://github.com/Chia-Network/chiavdf)
- [Chia VDF Documentation](https://docs.chia.net/chia-blockchain/consensus/proof-of-time/)
- [VDF Research](https://vdfresearch.org/)
- [Stanford VDF Survey](https://crypto.stanford.edu/~dabo/pubs/papers/VDFsurvey.pdf)

---

**Feedback welcome!** This is a foundational change and we want to get it right. Reply here or reach out directly.
