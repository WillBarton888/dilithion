/**
 * Comprehensive live test suite for wDIL and wDILV on Base Sepolia.
 * Tests all security invariants against the actual deployed contracts.
 *
 * Run: npx hardhat run scripts/live-test-suite.js --network baseSepolia
 */
const hre = require("hardhat");

let passed = 0;
let failed = 0;

function ok(name) {
  passed++;
  console.log(`  ✅ ${name}`);
}

function fail(name, err) {
  failed++;
  console.log(`  ❌ ${name}: ${err}`);
}

async function expectRevert(promise, name, expectedMsg) {
  try {
    const tx = await promise;
    await tx.wait();
    fail(name, "Transaction did NOT revert (expected revert)");
  } catch (e) {
    const msg = e.message || e.toString();
    if (expectedMsg && !msg.includes(expectedMsg)) {
      fail(name, `Reverted but wrong reason. Expected "${expectedMsg}", got: ${msg.slice(0, 200)}`);
    } else {
      ok(name);
    }
  }
}

function uniqueTxId(label) {
  // Each run gets unique txids based on timestamp
  const ts = Date.now().toString(36);
  return hre.ethers.encodeBytes32String(`${label}-${ts}`);
}

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log(`\nTest account: ${deployer.address}`);
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`ETH balance: ${hre.ethers.formatEther(balance)} ETH\n`);

  const wdil = await hre.ethers.getContractAt("WrappedDIL", process.env.WDIL_CONTRACT);
  const wdilv = await hre.ethers.getContractAt("WrappedDilV", process.env.WDILV_CONTRACT);

  // ══════════════════════════════════════════════════════════════
  console.log("═══ 1. CONTRACT BASICS ═══");
  // ══════════════════════════════════════════════════════════════

  // 1a. Verify names and symbols
  const dilName = await wdil.name();
  const dilSymbol = await wdil.symbol();
  const dilDecimals = await wdil.decimals();
  dilName === "Wrapped DIL" ? ok(`wDIL name = "${dilName}"`) : fail("wDIL name", dilName);
  dilSymbol === "wDIL" ? ok(`wDIL symbol = "${dilSymbol}"`) : fail("wDIL symbol", dilSymbol);
  dilDecimals === 8n ? ok(`wDIL decimals = ${dilDecimals}`) : fail("wDIL decimals", dilDecimals);

  const dilvName = await wdilv.name();
  const dilvSymbol = await wdilv.symbol();
  const dilvDecimals = await wdilv.decimals();
  dilvName === "Wrapped DilV" ? ok(`wDILV name = "${dilvName}"`) : fail("wDILV name", dilvName);
  dilvSymbol === "wDILV" ? ok(`wDILV symbol = "${dilvSymbol}"`) : fail("wDILV symbol", dilvSymbol);
  dilvDecimals === 8n ? ok(`wDILV decimals = ${dilvDecimals}`) : fail("wDILV decimals", dilvDecimals);

  // 1b. Verify ownership
  const dilOwner = await wdil.owner();
  const dilvOwner = await wdilv.owner();
  dilOwner === deployer.address ? ok("wDIL owner is deployer") : fail("wDIL owner", dilOwner);
  dilvOwner === deployer.address ? ok("wDILV owner is deployer") : fail("wDILV owner", dilvOwner);

  // 1c. Verify mint caps
  const dilDailyCap = await wdil.dailyMintCap();
  const dilMaxPerDeposit = await wdil.maxPerDeposit();
  dilDailyCap === 1_000_000_000_000n ? ok(`wDIL daily cap = ${dilDailyCap} (10,000 DIL)`) : fail("wDIL daily cap", dilDailyCap);
  dilMaxPerDeposit === 100_000_000_000n ? ok(`wDIL max/deposit = ${dilMaxPerDeposit} (1,000 DIL)`) : fail("wDIL max/deposit", dilMaxPerDeposit);

  const dilvDailyCap = await wdilv.dailyMintCap();
  const dilvMaxPerDeposit = await wdilv.maxPerDeposit();
  dilvDailyCap === 10_000_000_000_000n ? ok(`wDILV daily cap = ${dilvDailyCap} (100,000 DilV)`) : fail("wDILV daily cap", dilvDailyCap);
  dilvMaxPerDeposit === 1_000_000_000_000n ? ok(`wDILV max/deposit = ${dilvMaxPerDeposit} (10,000 DilV)`) : fail("wDILV max/deposit", dilvMaxPerDeposit);

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 2. REPLAY PROTECTION ═══");
  // ══════════════════════════════════════════════════════════════

  // 2a. The test-deposit-001 txid was already minted — try again
  const usedTxId = hre.ethers.encodeBytes32String("test-deposit-001");
  const isMinted = await wdil.minted(usedTxId);
  isMinted ? ok("minted[test-deposit-001] = true (from earlier test)") : fail("minted flag", "expected true");

  await expectRevert(
    wdil.mint(deployer.address, 100_000_000n, usedTxId),
    "Double-mint same txid reverts",
    "Already minted"
  );

  // 2b. Fresh txid should work
  const freshTxId = uniqueTxId("fresh");
  const freshNotMinted = await wdil.minted(freshTxId);
  !freshNotMinted ? ok("Fresh txid not yet minted") : fail("fresh txid check", "already minted?!");

  const mintTx = await wdil.mint(deployer.address, 50_000_000n, freshTxId); // 0.5 DIL
  const mintReceipt = await mintTx.wait();
  mintReceipt.status === 1 ? ok("Fresh mint succeeded (0.5 wDIL)") : fail("Fresh mint", "receipt status != 1");

  const nowMinted = await wdil.minted(freshTxId);
  nowMinted ? ok("minted[freshTxId] = true after mint") : fail("post-mint flag", "expected true");

  // 2c. Try double-minting the same fresh txid
  await expectRevert(
    wdil.mint(deployer.address, 50_000_000n, freshTxId),
    "Double-mint freshly used txid reverts",
    "Already minted"
  );

  // 2d. wDILV replay protection
  const usedDilvTxId = hre.ethers.encodeBytes32String("test-dilv-deposit-001");
  await expectRevert(
    wdilv.mint(deployer.address, 100_000_000n, usedDilvTxId),
    "wDILV double-mint same txid reverts",
    "Already minted"
  );

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 3. PER-DEPOSIT LIMIT ═══");
  // ══════════════════════════════════════════════════════════════

  // wDIL max is 1,000 DIL = 100,000,000,000
  const overLimit = 100_000_000_001n; // 1 ion over the limit
  await expectRevert(
    wdil.mint(deployer.address, overLimit, uniqueTxId("overlimit")),
    "wDIL mint > maxPerDeposit reverts",
    "Exceeds per-deposit limit"
  );

  // Exactly at limit should work
  const atLimitTx = await wdil.mint(deployer.address, 100_000_000_000n, uniqueTxId("atlimit")); // exactly 1,000 DIL
  const atLimitReceipt = await atLimitTx.wait();
  atLimitReceipt.status === 1 ? ok("wDIL mint exactly at maxPerDeposit succeeds (1,000 DIL)") : fail("at-limit mint", "failed");

  // wDILV max is 10,000 DilV = 1,000,000,000,000
  const overLimitDilv = 1_000_000_000_001n;
  await expectRevert(
    wdilv.mint(deployer.address, overLimitDilv, uniqueTxId("overlimitv")),
    "wDILV mint > maxPerDeposit reverts",
    "Exceeds per-deposit limit"
  );

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 4. BURN FLOW ═══");
  // ══════════════════════════════════════════════════════════════

  const balBefore = await wdil.balanceOf(deployer.address);
  console.log(`  Balance before burn: ${hre.ethers.formatUnits(balBefore, 8)} wDIL`);

  // Burn 0.5 wDIL with a native address
  const burnAmount = 50_000_000n; // 0.5 DIL
  const nativeAddr = "DTestBurnAddress12345678901234";
  const burnTx = await wdil.burn(burnAmount, nativeAddr);
  const burnReceipt = await burnTx.wait();
  burnReceipt.status === 1 ? ok("Burn 0.5 wDIL succeeded") : fail("burn", "receipt status != 1");

  const balAfter = await wdil.balanceOf(deployer.address);
  balAfter === balBefore - burnAmount ? ok(`Balance decreased by 0.5 wDIL (now ${hre.ethers.formatUnits(balAfter, 8)})`) : fail("burn balance", `expected ${balBefore - burnAmount}, got ${balAfter}`);

  // Check BridgeBurn event was emitted
  const burnEvents = burnReceipt.logs.filter(log => {
    try {
      const parsed = wdil.interface.parseLog(log);
      return parsed && parsed.name === "BridgeBurn";
    } catch { return false; }
  });
  burnEvents.length === 1 ? ok("BridgeBurn event emitted") : fail("BridgeBurn event", `got ${burnEvents.length} events`);

  if (burnEvents.length > 0) {
    const parsed = wdil.interface.parseLog(burnEvents[0]);
    parsed.args.nativeAddress === nativeAddr
      ? ok(`BridgeBurn.nativeAddress = "${nativeAddr}"`)
      : fail("BridgeBurn.nativeAddress", parsed.args.nativeAddress);
  }

  // 4b. Burn with empty native address should revert
  await expectRevert(
    wdil.burn(10_000_000n, ""),
    "Burn with empty native address reverts",
    "Empty native address"
  );

  // 4c. Burn more than balance should revert
  const hugeAmount = balAfter + 1n;
  await expectRevert(
    wdil.burn(hugeAmount, "DTestAddress"),
    "Burn more than balance reverts",
    "" // ERC20 will revert with insufficient balance
  );

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 5. PAUSE / UNPAUSE ═══");
  // ══════════════════════════════════════════════════════════════

  // Pause the contract
  const pauseTx = await wdil.pause();
  await pauseTx.wait();
  const isPaused = await wdil.paused();
  isPaused ? ok("Contract paused") : fail("pause", "not paused");

  // Mint should fail when paused
  await expectRevert(
    wdil.mint(deployer.address, 10_000_000n, uniqueTxId("paused")),
    "Mint while paused reverts",
    "" // RPC may strip custom error — just check it reverts
  );

  // Burn should fail when paused
  await expectRevert(
    wdil.burn(10_000_000n, "DTestAddress"),
    "Burn while paused reverts",
    "" // RPC may strip custom error — just check it reverts
  );

  // Unpause
  const unpauseTx = await wdil.unpause();
  await unpauseTx.wait();
  // Verify unpause by attempting a mint (more reliable than reading paused() which can be RPC-cached)

  // Mint should work again after unpause
  const afterPauseTx = await wdil.mint(deployer.address, 10_000_000n, uniqueTxId("unpaused"));
  const afterPauseReceipt = await afterPauseTx.wait();
  afterPauseReceipt.status === 1 ? ok("Mint works after unpause") : fail("post-unpause mint", "failed");

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 6. ADMIN CONTROLS ═══");
  // ══════════════════════════════════════════════════════════════

  // Update daily mint cap — test by setting a low cap, then trying to exceed it
  const lowCap = 1_000_000n; // 0.01 DIL (very low)
  const setCapTx = await wdil.setDailyMintCap(lowCap);
  await setCapTx.wait();

  // Mint should fail if it exceeds the new low cap
  await expectRevert(
    wdil.mint(deployer.address, 10_000_000n, uniqueTxId("captest")), // 0.1 DIL > 0.01 cap
    "setDailyMintCap enforced (mint > new low cap reverts)",
    ""
  );

  // Reset it back
  const resetCapTx = await wdil.setDailyMintCap(1_000_000_000_000n);
  await resetCapTx.wait();
  ok("Reset daily cap to original 10,000 DIL");

  // Update max per deposit — test by setting low, then trying to exceed
  const lowMax = 1_000_000n; // 0.01 DIL
  const setMaxTx = await wdil.setMaxPerDeposit(lowMax);
  await setMaxTx.wait();

  await expectRevert(
    wdil.mint(deployer.address, 10_000_000n, uniqueTxId("maxtest")), // 0.1 DIL > 0.01 max
    "setMaxPerDeposit enforced (mint > new low max reverts)",
    ""
  );

  // Reset it back
  const resetMaxTx = await wdil.setMaxPerDeposit(100_000_000_000n);
  await resetMaxTx.wait();
  ok("Reset maxPerDeposit to original 1,000 DIL");

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 7. ERC-20 TRANSFER ═══");
  // ══════════════════════════════════════════════════════════════

  // Transfer wDIL to a random address (simulates user trading)
  const recipient = "0x000000000000000000000000000000000000dEaD"; // burn address
  const transferAmount = 10_000_000n; // 0.1 DIL
  const balBeforeTransfer = await wdil.balanceOf(deployer.address);
  const transferTx = await wdil.transfer(recipient, transferAmount);
  const transferReceipt = await transferTx.wait();
  transferReceipt.status === 1 ? ok("ERC-20 transfer succeeded") : fail("transfer", "failed");

  const deadBal = await wdil.balanceOf(recipient);
  deadBal === transferAmount ? ok(`Recipient balance = ${hre.ethers.formatUnits(deadBal, 8)} wDIL`) : fail("recipient balance", deadBal);

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ 8. SUPPLY INTEGRITY ═══");
  // ══════════════════════════════════════════════════════════════

  const totalSupply = await wdil.totalSupply();
  const deployerBal = await wdil.balanceOf(deployer.address);
  const deadBalance = await wdil.balanceOf(recipient);
  const accountedFor = deployerBal + deadBalance;
  console.log(`  Total supply: ${hre.ethers.formatUnits(totalSupply, 8)} wDIL`);
  console.log(`  Deployer:     ${hre.ethers.formatUnits(deployerBal, 8)} wDIL`);
  console.log(`  Dead addr:    ${hre.ethers.formatUnits(deadBalance, 8)} wDIL`);
  totalSupply === accountedFor
    ? ok("Total supply = sum of all balances")
    : fail("supply integrity", `supply=${totalSupply}, accounted=${accountedFor}`);

  // ══════════════════════════════════════════════════════════════
  console.log("\n═══ RESULTS ═══");
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${passed + failed}`);
  if (failed > 0) {
    console.log("\n  ⚠️  SOME TESTS FAILED — review above");
    process.exitCode = 1;
  } else {
    console.log("\n  🎉 ALL TESTS PASSED");
  }

  // Print final balances
  const finalDilBal = await wdil.balanceOf(deployer.address);
  const finalDilvBal = await wdilv.balanceOf(deployer.address);
  const finalEth = await hre.ethers.provider.getBalance(deployer.address);
  console.log(`\nFinal state:`);
  console.log(`  wDIL:  ${hre.ethers.formatUnits(finalDilBal, 8)}`);
  console.log(`  wDILV: ${hre.ethers.formatUnits(finalDilvBal, 8)}`);
  console.log(`  ETH:   ${hre.ethers.formatEther(finalEth)}`);
}

main().catch(e => {
  console.error("Fatal error:", e);
  process.exitCode = 1;
});
