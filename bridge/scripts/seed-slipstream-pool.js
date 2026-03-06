/**
 * Seed wDIL/WETH Slipstream (concentrated liquidity) pool on Aerodrome.
 *
 * This script:
 *   1. Wraps ETH → WETH
 *   2. Approves wDIL + WETH to the NonfungiblePositionManager
 *   3. Mints a new concentrated liquidity position (creates pool if needed)
 *
 * Usage:
 *   npx hardhat run scripts/seed-slipstream-pool.js --network baseMainnet
 *
 * Requirements:
 *   - Deployer has wDIL balance (from bridge minting)
 *   - Deployer has ETH balance (for WETH + gas)
 */

const hre = require("hardhat");

// ── Aerodrome Slipstream addresses (Base mainnet) ────────────────────
const POSITION_MANAGER = "0xa990C6a764b73BF43cee5Bb40339c3322FB9D55F";
const WETH9            = "0x4200000000000000000000000000000000000006";

// ── Pool parameters ──────────────────────────────────────────────────
const TICK_SPACING = 200;  // CL200 — standard for volatile pairs

// Price: 1 DIL = 0.00005 ETH ($0.105 at $2,100/ETH)
// Both tokens use 8 decimals (wDIL) and 18 decimals (WETH), so we need to
// account for the decimal difference in the price calculation.
//
// Uniswap V3 / Slipstream price convention:
//   price = token1 / token0 (in their smallest units)
//   sqrtPriceX96 = sqrt(price) * 2^96
//
// Token ordering: Slipstream requires token0 < token1 (by address).
// WETH9 = 0x4200...0006. wDIL will have a different address.
// We determine token0/token1 at runtime.

// Amount to seed
const WDIL_AMOUNT = 5_000n * 100_000_000n;  // 5,000 wDIL in ions (8 decimals)
const ETH_AMOUNT  = hre.ethers.parseEther("0.25");  // 0.25 ETH

// ── ABI fragments ────────────────────────────────────────────────────
const WETH_ABI = [
  "function deposit() external payable",
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address) external view returns (uint256)",
];

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function balanceOf(address) external view returns (uint256)",
  "function decimals() external view returns (uint8)",
];

const POSITION_MANAGER_ABI = [
  `function mint(tuple(
    address token0,
    address token1,
    int24 tickSpacing,
    int24 tickLower,
    int24 tickUpper,
    uint256 amount0Desired,
    uint256 amount1Desired,
    uint256 amount0Min,
    uint256 amount1Min,
    address recipient,
    uint256 deadline,
    uint160 sqrtPriceX96
  ) params) external payable returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)`,
];

// ── Helper functions ─────────────────────────────────────────────────

/**
 * Calculate sqrtPriceX96 from a price ratio.
 * price = token1Amount / token0Amount (in smallest units)
 */
function calcSqrtPriceX96(price) {
  // sqrtPriceX96 = sqrt(price) * 2^96
  // Using BigInt math for precision
  const sqrtPrice = Math.sqrt(Number(price));
  const Q96 = 2n ** 96n;
  return BigInt(Math.floor(sqrtPrice * Number(Q96)));
}

/**
 * Calculate tick from price.
 * tick = floor(log(sqrt(price)) / log(sqrt(1.0001)))
 *      = floor(log(price) / log(1.0001) / 2) * 2
 * Adjusted to nearest valid tick (multiple of tickSpacing).
 */
function priceToTick(price, tickSpacing) {
  const tick = Math.floor(Math.log(Number(price)) / Math.log(1.0001));
  // Round down to nearest tickSpacing multiple
  return Math.floor(tick / tickSpacing) * tickSpacing;
}

async function main() {
  const [signer] = await hre.ethers.getSigners();
  const wdilAddress = process.env.WDIL_CONTRACT;

  if (!wdilAddress) {
    throw new Error("WDIL_CONTRACT not set in .env");
  }

  console.log("=== Aerodrome Slipstream Pool Seeder ===");
  console.log(`Deployer: ${signer.address}`);
  console.log(`wDIL:     ${wdilAddress}`);
  console.log(`WETH:     ${WETH9}`);

  // Determine token ordering (Slipstream requires token0 < token1)
  const wdilAddr = wdilAddress.toLowerCase();
  const wethAddr = WETH9.toLowerCase();
  const wdilIsToken0 = wdilAddr < wethAddr;

  const token0 = wdilIsToken0 ? wdilAddress : WETH9;
  const token1 = wdilIsToken0 ? WETH9 : wdilAddress;

  console.log(`token0: ${token0} (${wdilIsToken0 ? "wDIL" : "WETH"})`);
  console.log(`token1: ${token1} (${wdilIsToken0 ? "WETH" : "wDIL"})`);

  // Connect to contracts
  const weth = new hre.ethers.Contract(WETH9, WETH_ABI, signer);
  const wdil = new hre.ethers.Contract(wdilAddress, ERC20_ABI, signer);
  const posManager = new hre.ethers.Contract(POSITION_MANAGER, POSITION_MANAGER_ABI, signer);

  // Check balances
  const wdilBal = await wdil.balanceOf(signer.address);
  const ethBal = await hre.ethers.provider.getBalance(signer.address);
  const wdilDecimals = await wdil.decimals();

  console.log(`\nBalances:`);
  console.log(`  wDIL: ${hre.ethers.formatUnits(wdilBal, wdilDecimals)} wDIL`);
  console.log(`  ETH:  ${hre.ethers.formatEther(ethBal)} ETH`);

  if (wdilBal < WDIL_AMOUNT) {
    throw new Error(`Insufficient wDIL: have ${wdilBal}, need ${WDIL_AMOUNT}`);
  }
  if (ethBal < ETH_AMOUNT + hre.ethers.parseEther("0.01")) {
    throw new Error(`Insufficient ETH: have ${ethBal}, need ${ETH_AMOUNT} + gas`);
  }

  // Step 1: Wrap ETH → WETH
  console.log(`\nStep 1: Wrapping ${hre.ethers.formatEther(ETH_AMOUNT)} ETH → WETH...`);
  const wrapTx = await weth.deposit({ value: ETH_AMOUNT });
  await wrapTx.wait();
  console.log("  Done.");

  // Step 2: Approve tokens to Position Manager
  console.log("Step 2: Approving tokens...");
  const approveDil = await wdil.approve(POSITION_MANAGER, WDIL_AMOUNT);
  const approveWeth = await weth.approve(POSITION_MANAGER, ETH_AMOUNT);
  await Promise.all([approveDil.wait(), approveWeth.wait()]);
  console.log("  Done.");

  // Step 3: Calculate price and tick range
  //
  // Target: 1 wDIL (8 decimals) = 0.00005 WETH (18 decimals)
  // In smallest units: 1e8 wDIL-ions = 0.00005 * 1e18 = 5e13 WETH-wei
  // So: price(token1/token0) depends on ordering.
  //
  // If wDIL is token0: price = WETH/wDIL = (5e13 wei) / (1e8 ions) = 5e5
  // If WETH is token0: price = wDIL/WETH = (1e8 ions) / (5e13 wei) = 2e-6

  let price, amount0Desired, amount1Desired;

  if (wdilIsToken0) {
    // token0=wDIL, token1=WETH, price = WETH per wDIL (in smallest units)
    price = 5e5;  // 5e13 / 1e8
    amount0Desired = WDIL_AMOUNT;
    amount1Desired = ETH_AMOUNT;
  } else {
    // token0=WETH, token1=wDIL, price = wDIL per WETH (in smallest units)
    price = 1e8 / 5e13;  // = 2e-6
    amount0Desired = ETH_AMOUNT;
    amount1Desired = WDIL_AMOUNT;
  }

  const sqrtPriceX96 = calcSqrtPriceX96(price);
  const currentTick = priceToTick(price, TICK_SPACING);

  // ±50% range in ticks
  // +50% price → tick increases by log(1.5)/log(1.0001) ≈ 4055
  // -50% price → tick decreases by log(0.5)/log(1.0001) ≈ -6932
  // Round to tickSpacing
  const tickRange50PctUp = Math.floor(Math.log(1.5) / Math.log(1.0001) / TICK_SPACING) * TICK_SPACING;
  const tickRange50PctDn = Math.floor(Math.log(0.5) / Math.log(1.0001) / TICK_SPACING) * TICK_SPACING;

  const tickLower = currentTick + tickRange50PctDn;
  const tickUpper = currentTick + tickRange50PctUp;

  console.log(`\nStep 3: Price calculation:`);
  console.log(`  Target price: 1 DIL = 0.00005 ETH ($0.105)`);
  console.log(`  Price (token1/token0): ${price}`);
  console.log(`  sqrtPriceX96: ${sqrtPriceX96}`);
  console.log(`  Current tick: ${currentTick}`);
  console.log(`  Tick range: [${tickLower}, ${tickUpper}]`);
  console.log(`  Price range: $${(0.105 * 0.5).toFixed(4)} — $${(0.105 * 1.5).toFixed(4)} per DIL`);

  // Step 4: Mint position (creates pool if it doesn't exist)
  console.log("\nStep 4: Creating pool + minting position...");
  const deadline = Math.floor(Date.now() / 1000) + 600; // 10 min

  const mintParams = {
    token0,
    token1,
    tickSpacing: TICK_SPACING,
    tickLower,
    tickUpper,
    amount0Desired,
    amount1Desired,
    amount0Min: 0n,  // Accept any amount (first LP, no slippage concern)
    amount1Min: 0n,
    recipient: signer.address,
    deadline,
    sqrtPriceX96,  // Non-zero = create + initialize pool
  };

  console.log("  Params:", JSON.stringify(mintParams, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));

  const tx = await posManager.mint(mintParams, { gasLimit: 5_000_000 });
  const receipt = await tx.wait();

  console.log(`\n=== SUCCESS ===`);
  console.log(`Transaction: ${receipt.hash}`);
  console.log(`Gas used: ${receipt.gasUsed}`);
  console.log(`\nPool created with ${hre.ethers.formatUnits(WDIL_AMOUNT, 8)} wDIL + ${hre.ethers.formatEther(ETH_AMOUNT)} ETH`);
  console.log(`Price range: $0.0525 — $0.1575 per DIL (±50%)`);
  console.log(`\nView on Aerodrome: https://aerodrome.finance/`);
  console.log(`View on BaseScan: https://basescan.org/tx/${receipt.hash}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
