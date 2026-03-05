const hre = require("hardhat");
require("dotenv").config();

async function main() {
  const wdilAddress = process.env.WDIL_CONTRACT;
  const wdilvAddress = process.env.WDILV_CONTRACT;

  if (wdilAddress) {
    console.log(`Verifying WrappedDIL at ${wdilAddress}...`);
    try {
      await hre.run("verify:verify", {
        address: wdilAddress,
        constructorArguments: [1_000_000_000_000n, 100_000_000_000n],
      });
      console.log("WrappedDIL verified successfully");
    } catch (e) {
      console.log(`WrappedDIL verification: ${e.message}`);
    }
  }

  if (wdilvAddress) {
    console.log(`Verifying WrappedDilV at ${wdilvAddress}...`);
    try {
      await hre.run("verify:verify", {
        address: wdilvAddress,
        constructorArguments: [10_000_000_000_000n, 1_000_000_000_000n],
      });
      console.log("WrappedDilV verified successfully");
    } catch (e) {
      console.log(`WrappedDilV verification: ${e.message}`);
    }
  }

  if (!wdilAddress && !wdilvAddress) {
    console.log("Set WDIL_CONTRACT and/or WDILV_CONTRACT in .env first");
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
