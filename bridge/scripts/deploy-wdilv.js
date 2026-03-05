const hre = require("hardhat");

async function main() {
  // 100,000 DilV daily cap = 100,000 * 10^8 = 10,000,000,000,000
  const dailyMintCap = 10_000_000_000_000n;
  // 10,000 DilV per-deposit beta limit = 10,000 * 10^8 = 1,000,000,000,000
  const maxPerDeposit = 1_000_000_000_000n;

  console.log("Deploying WrappedDilV (wDILV)...");
  console.log(`  Daily mint cap: ${dailyMintCap} (${Number(dailyMintCap) / 1e8} DilV)`);
  console.log(`  Max per deposit: ${maxPerDeposit} (${Number(maxPerDeposit) / 1e8} DilV)`);

  const WrappedDilV = await hre.ethers.getContractFactory("WrappedDilV");
  const wdilv = await WrappedDilV.deploy(dailyMintCap, maxPerDeposit);
  await wdilv.waitForDeployment();

  const address = await wdilv.getAddress();
  console.log(`\nWrappedDilV deployed to: ${address}`);
  console.log(`\nAdd to .env:\n  WDILV_CONTRACT=${address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
