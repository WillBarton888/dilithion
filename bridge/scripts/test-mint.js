const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Minting from:", deployer.address);

  const wdil = await hre.ethers.getContractAt("WrappedDIL", process.env.WDIL_CONTRACT);

  // Mint 1 DIL (= 100,000,000 in 8-decimal units) with a fake native txid
  const amount = 100_000_000n; // 1 DIL
  const fakeTxId = hre.ethers.encodeBytes32String("test-deposit-001");

  console.log(`Minting 1 wDIL to ${deployer.address}...`);
  const tx = await wdil.mint(deployer.address, amount, fakeTxId);
  console.log("Tx hash:", tx.hash);

  const receipt = await tx.wait();
  console.log("Confirmed in block:", receipt.blockNumber);

  const balance = await wdil.balanceOf(deployer.address);
  console.log(`wDIL balance: ${hre.ethers.formatUnits(balance, 8)} wDIL`);

  // Check it shows up as minted (replay protection)
  const isMinted = await wdil.minted(fakeTxId);
  console.log("Replay protection (minted[txid]):", isMinted);
}

main().catch(console.error);
