const hre = require("hardhat");

async function main() {
  // 10,000 DIL daily cap = 10,000 * 10^8 = 1,000,000,000,000
  const dailyMintCap = 1_000_000_000_000n;
  // 1,000 DIL per-deposit beta limit = 1,000 * 10^8 = 100,000,000,000
  const maxPerDeposit = 100_000_000_000n;

  console.log("Deploying WrappedDIL (wDIL)...");
  console.log(`  Daily mint cap: ${dailyMintCap} (${Number(dailyMintCap) / 1e8} DIL)`);
  console.log(`  Max per deposit: ${maxPerDeposit} (${Number(maxPerDeposit) / 1e8} DIL)`);

  const WrappedDIL = await hre.ethers.getContractFactory("WrappedDIL");
  const wdil = await WrappedDIL.deploy(dailyMintCap, maxPerDeposit);
  await wdil.waitForDeployment();

  const address = await wdil.getAddress();
  console.log(`\nWrappedDIL deployed to: ${address}`);
  console.log(`\nAdd to .env:\n  WDIL_CONTRACT=${address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
