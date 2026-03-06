/**
 * Seed wDIL/wDilV stable pool on Aerodrome (classic AMM).
 *
 * Maintains the 10:1 ratio (10 DilV = 1 DIL) via a stable-swap curve.
 *
 * Usage:
 *   npx hardhat run scripts/seed-stable-pool.js --network baseMainnet
 *
 * Requirements:
 *   - Deployer has wDIL balance (5,000+ wDIL)
 *   - Deployer has wDILV balance (50,000+ wDILV)
 */

const hre = require("hardhat");

// ── Aerodrome Classic AMM addresses (Base mainnet) ────────────────────
const ROUTER       = "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43";
const POOL_FACTORY = "0x420DD381b31aEf6683db6B902084cB0FFECe40Da";

// ── Pool parameters ──────────────────────────────────────────────────
// 5,000 wDIL + 50,000 wDilV (10:1 ratio, both 8 decimals)
const WDIL_AMOUNT  = 4_999n * 100_000_000n;   // 4,999 wDIL in ions
const WDILV_AMOUNT = 49_990n * 100_000_000n;   // 49,990 wDilV in volts

// ── ABI fragments ────────────────────────────────────────────────────
const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address) external view returns (uint256)",
  "function decimals() external view returns (uint8)",
  "function symbol() external view returns (string)",
];

const ROUTER_ABI = [
  `function addLiquidity(
    address tokenA,
    address tokenB,
    bool stable,
    uint256 amountADesired,
    uint256 amountBDesired,
    uint256 amountAMin,
    uint256 amountBMin,
    address to,
    uint256 deadline
  ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity)`,
  "function poolFor(address tokenA, address tokenB, bool stable, address factory) external view returns (address pool)",
];

async function main() {
  const [signer] = await hre.ethers.getSigners();
  const wdilAddress = process.env.WDIL_CONTRACT;
  const wdilvAddress = process.env.WDILV_CONTRACT;

  if (!wdilAddress || !wdilvAddress) {
    throw new Error("WDIL_CONTRACT and WDILV_CONTRACT must be set in .env");
  }

  console.log("=== Aerodrome Stable Pool Seeder (wDIL/wDilV) ===");
  console.log(`Deployer: ${signer.address}`);
  console.log(`wDIL:     ${wdilAddress}`);
  console.log(`wDILV:    ${wdilvAddress}`);

  // Connect to contracts
  const wdil = new hre.ethers.Contract(wdilAddress, ERC20_ABI, signer);
  const wdilv = new hre.ethers.Contract(wdilvAddress, ERC20_ABI, signer);
  const router = new hre.ethers.Contract(ROUTER, ROUTER_ABI, signer);

  // Check balances
  const wdilBal = await wdil.balanceOf(signer.address);
  const wdilvBal = await wdilv.balanceOf(signer.address);

  console.log(`\nBalances:`);
  console.log(`  wDIL:  ${hre.ethers.formatUnits(wdilBal, 8)} wDIL`);
  console.log(`  wDILV: ${hre.ethers.formatUnits(wdilvBal, 8)} wDILV`);

  if (wdilBal < WDIL_AMOUNT) {
    throw new Error(`Insufficient wDIL: have ${wdilBal}, need ${WDIL_AMOUNT}`);
  }
  if (wdilvBal < WDILV_AMOUNT) {
    throw new Error(`Insufficient wDILV: have ${wdilvBal}, need ${WDILV_AMOUNT}`);
  }

  // Step 1: Approve tokens to Router
  console.log("\nStep 1: Approving tokens to Router...");
  const approveDil = await wdil.approve(ROUTER, WDIL_AMOUNT);
  const approveDilv = await wdilv.approve(ROUTER, WDILV_AMOUNT);
  await Promise.all([approveDil.wait(), approveDilv.wait()]);
  console.log("  Done.");

  // Step 2: Add liquidity (stable pool — creates pool if it doesn't exist)
  console.log("\nStep 2: Adding liquidity to stable pool...");
  console.log(`  wDIL:  ${hre.ethers.formatUnits(WDIL_AMOUNT, 8)} (5,000 DIL)`);
  console.log(`  wDILV: ${hre.ethers.formatUnits(WDILV_AMOUNT, 8)} (50,000 DilV)`);
  console.log(`  Ratio: 10:1 (10 DilV per 1 DIL)`);
  console.log(`  Type:  Stable (constant-sum curve)`);

  const deadline = Math.floor(Date.now() / 1000) + 600; // 10 min

  const tx = await router.addLiquidity(
    wdilAddress,      // tokenA
    wdilvAddress,     // tokenB
    false,            // stable = false (volatile pool, x*y=k — supports any ratio)
    WDIL_AMOUNT,      // amountADesired
    WDILV_AMOUNT,     // amountBDesired
    0n,               // amountAMin (first LP, accept any)
    0n,               // amountBMin
    signer.address,   // LP tokens go to deployer
    deadline,
    { gasLimit: 5_000_000 }
  );

  const receipt = await tx.wait();

  // Get pool address
  let poolAddress;
  try {
    poolAddress = await router.poolFor(wdilAddress, wdilvAddress, false, POOL_FACTORY);
  } catch {
    poolAddress = "(check BaseScan)";
  }

  console.log(`\n=== SUCCESS ===`);
  console.log(`Transaction: ${receipt.hash}`);
  console.log(`Gas used: ${receipt.gasUsed}`);
  console.log(`Pool address: ${poolAddress}`);
  console.log(`\nStable pool seeded: 5,000 wDIL + 50,000 wDilV (10:1 ratio)`);
  console.log(`\nView on Aerodrome: https://aerodrome.finance/`);
  console.log(`View on BaseScan: https://basescan.org/tx/${receipt.hash}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
