const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Minting from:", deployer.address);

  const wdilv = await hre.ethers.getContractAt("WrappedDilV", process.env.WDILV_CONTRACT);

  // Mint 10 DilV (= 1,000,000,000 in 8-decimal units) with a fake native txid
  const amount = 1_000_000_000n; // 10 DilV
  const fakeTxId = hre.ethers.encodeBytes32String("test-dilv-deposit-001");

  console.log(`Minting 10 wDILV to ${deployer.address}...`);
  const tx = await wdilv.mint(deployer.address, amount, fakeTxId);
  console.log("Tx hash:", tx.hash);

  const receipt = await tx.wait();
  console.log("Confirmed in block:", receipt.blockNumber);

  const balance = await wdilv.balanceOf(deployer.address);
  console.log(`wDILV balance: ${hre.ethers.formatUnits(balance, 8)} wDILV`);
}

main().catch(console.error);
