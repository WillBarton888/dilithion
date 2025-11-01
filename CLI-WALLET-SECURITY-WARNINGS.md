# CRITICAL SECURITY WARNINGS FOR CLI WALLET

## Insert this section at the TOP of CLI-WALLET-GUIDE.md (after title, before Overview)

---

## CRITICAL SECURITY WARNINGS

### BEFORE USING THIS WALLET - READ CAREFULLY

**PERMANENT LOSS RISK:** Sending cryptocurrency to the wrong address results in PERMANENT, IRREVERSIBLE loss of funds. There is NO "undo" button.

### Safety Requirements

1. **ALWAYS VERIFY ADDRESSES:**
   - Copy-paste addresses, NEVER type them manually
   - Verify the ENTIRE address character-by-character
   - Confirm address with recipient through a second channel (phone, etc.)

2. **TEST WITH SMALL AMOUNTS FIRST:**
   - Always send a small test transaction first (e.g., 0.01 DIL)
   - Wait for confirmation
   - Confirm recipient received it
   - Only then send the full amount

3. **UNDERSTAND THE RISKS:**
   - These are command-line tools - one typo can lose funds forever
   - Address validation is done, but human error is still possible
   - If you're not comfortable with command-line tools, use a GUI wallet

4. **NOT FOR BEGINNERS:**
   - Requires understanding of cryptocurrency concepts
   - Requires careful attention to detail
   - Mistakes are expensive and permanent

### Safety Checklist (Complete Before Every Send)

- [ ] Recipient address is EXACTLY correct (character-by-character check)
- [ ] Amount is correct including decimal places
- [ ] You have confirmed the address with recipient
- [ ] You've tested with small amount first (for new addresses)
- [ ] You understand this is PERMANENT and IRREVERSIBLE
- [ ] You have sufficient balance (including fee buffer)
- [ ] This is NOT your entire balance (in case of error)

### What This Wallet DOES Validate

- Address format (must start with DLT1, correct length)
- Address character set (alphanumeric only)
- Amount format (positive number, max 8 decimals)
- Amount range (greater than zero, less than max supply)

### What This Wallet CANNOT Validate

- Whether the address exists or is active
- Whether you typed the address correctly
- Whether the address belongs to intended recipient
- Whether recipient can access the address
- Whether the blockchain will accept the transaction

### If You're Not Sure - DON'T SEND

**When in doubt, ask for help first. Better to wait than to lose funds forever.**

---

