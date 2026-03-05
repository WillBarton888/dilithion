/**
 * Test the full burn flow (simulates what the bridge UI does via MetaMask).
 * Burns wDIL and verifies the BridgeBurn event contains the native address.
 */
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const wdil = await hre.ethers.getContractAt("WrappedDIL", process.env.WDIL_CONTRACT);

  const balBefore = await wdil.balanceOf(deployer.address);
  console.log(`wDIL balance before: ${hre.ethers.formatUnits(balBefore, 8)}`);

  const burnAmount = 100_000_000n; // 1 DIL
  const nativeAddress = "DTmbtug99yyzuSbTHzs2RGMkX1RdKRfR3o"; // example DIL address

  console.log(`\nBurning 1 wDIL → native address: ${nativeAddress}`);
  const tx = await wdil.burn(burnAmount, nativeAddress);
  console.log(`Tx hash: ${tx.hash}`);

  const receipt = await tx.wait();
  console.log(`Block: ${receipt.blockNumber}, Gas used: ${receipt.gasUsed}`);

  // Parse BridgeBurn event
  const burnEvent = receipt.logs
    .map(log => { try { return wdil.interface.parseLog(log); } catch { return null; } })
    .find(e => e && e.name === "BridgeBurn");

  if (burnEvent) {
    console.log(`\nBridgeBurn event:`);
    console.log(`  from:          ${burnEvent.args.from}`);
    console.log(`  amount:        ${burnEvent.args.amount} (${hre.ethers.formatUnits(burnEvent.args.amount, 8)} DIL)`);
    console.log(`  nativeAddress: ${burnEvent.args.nativeAddress}`);

    // Verify the relayer would see correct data
    console.log(`\n✅ Relayer would process this as:`);
    console.log(`  Chain: dil`);
    console.log(`  Send ${hre.ethers.formatUnits(burnEvent.args.amount, 8)} DIL to ${burnEvent.args.nativeAddress}`);
    console.log(`  From Base burn tx: ${receipt.hash}`);
  } else {
    console.log("❌ BridgeBurn event NOT found in receipt!");
  }

  const balAfter = await wdil.balanceOf(deployer.address);
  console.log(`\nwDIL balance after: ${hre.ethers.formatUnits(balAfter, 8)}`);

  // Also test wDILV burn
  const wdilv = await hre.ethers.getContractAt("WrappedDilV", process.env.WDILV_CONTRACT);
  const dilvBal = await wdilv.balanceOf(deployer.address);
  console.log(`\n--- wDILV burn test ---`);
  console.log(`wDILV balance: ${hre.ethers.formatUnits(dilvBal, 8)}`);

  if (dilvBal > 0n) {
    const dilvBurnAmount = 100_000_000n; // 1 DilV
    const dilvNativeAddr = "VTestBurnAddress12345678901234";
    const dilvTx = await wdilv.burn(dilvBurnAmount, dilvNativeAddr);
    const dilvReceipt = await dilvTx.wait();

    const dilvBurnEvent = dilvReceipt.logs
      .map(log => { try { return wdilv.interface.parseLog(log); } catch { return null; } })
      .find(e => e && e.name === "BridgeBurn");

    if (dilvBurnEvent) {
      console.log(`✅ wDILV BridgeBurn event: ${hre.ethers.formatUnits(dilvBurnEvent.args.amount, 8)} DilV → ${dilvBurnEvent.args.nativeAddress}`);
    } else {
      console.log("❌ wDILV BridgeBurn event NOT found!");
    }
  }
}

main().catch(console.error);
