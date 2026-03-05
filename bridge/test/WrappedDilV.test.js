const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("WrappedDilV", function () {
  let wdilv;
  let owner, user1, user2;

  // 100,000 DilV daily cap
  const DAILY_CAP = 10_000_000_000_000n;
  // 10,000 DilV per-deposit limit
  const MAX_PER_DEPOSIT = 1_000_000_000_000n;
  // 1 DilV = 10^8
  const ONE_DILV = 100_000_000n;

  const TXID_1 = ethers.id("native-txid-1");
  const TXID_2 = ethers.id("native-txid-2");

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();

    const WrappedDilV = await ethers.getContractFactory("WrappedDilV");
    wdilv = await WrappedDilV.deploy(DAILY_CAP, MAX_PER_DEPOSIT);
    await wdilv.waitForDeployment();
  });

  describe("Deployment", function () {
    it("should have correct name, symbol, and decimals", async function () {
      expect(await wdilv.name()).to.equal("Wrapped DilV");
      expect(await wdilv.symbol()).to.equal("wDILV");
      expect(await wdilv.decimals()).to.equal(8);
    });

    it("should set daily mint cap and max per deposit", async function () {
      expect(await wdilv.dailyMintCap()).to.equal(DAILY_CAP);
      expect(await wdilv.maxPerDeposit()).to.equal(MAX_PER_DEPOSIT);
    });
  });

  describe("Minting", function () {
    it("should allow owner to mint", async function () {
      const amount = 1000n * ONE_DILV;
      await wdilv.mint(user1.address, amount, TXID_1);
      expect(await wdilv.balanceOf(user1.address)).to.equal(amount);
    });

    it("should reject duplicate nativeTxId", async function () {
      await wdilv.mint(user1.address, 100n * ONE_DILV, TXID_1);
      await expect(
        wdilv.mint(user1.address, 100n * ONE_DILV, TXID_1)
      ).to.be.revertedWith("Already minted for this txid");
    });

    it("should reject mint exceeding per-deposit limit", async function () {
      await expect(
        wdilv.mint(user1.address, MAX_PER_DEPOSIT + 1n, TXID_1)
      ).to.be.revertedWith("Exceeds per-deposit limit");
    });

    it("should enforce daily mint cap", async function () {
      const numChunks = DAILY_CAP / MAX_PER_DEPOSIT;
      for (let i = 0n; i < numChunks; i++) {
        await wdilv.mint(user1.address, MAX_PER_DEPOSIT, ethers.id(`tx-${i}`));
      }
      await expect(
        wdilv.mint(user1.address, ONE_DILV, ethers.id("overflow"))
      ).to.be.revertedWith("Daily mint cap exceeded");
    });

    it("should reset daily cap after 24 hours", async function () {
      const numChunks = DAILY_CAP / MAX_PER_DEPOSIT;
      for (let i = 0n; i < numChunks; i++) {
        await wdilv.mint(user1.address, MAX_PER_DEPOSIT, ethers.id(`d1-${i}`));
      }
      await time.increase(86401);
      await wdilv.mint(user1.address, ONE_DILV, ethers.id("d2-0"));
      expect(await wdilv.mintedToday()).to.equal(ONE_DILV);
    });
  });

  describe("Burning", function () {
    it("should allow burn with native address", async function () {
      await wdilv.mint(user1.address, 500n * ONE_DILV, TXID_1);
      await expect(
        wdilv.connect(user1).burn(200n * ONE_DILV, "D6kuPWxvnbEbGcS4dSjVCzq2abeGcHTqVH")
      )
        .to.emit(wdilv, "BridgeBurn")
        .withArgs(user1.address, 200n * ONE_DILV, "D6kuPWxvnbEbGcS4dSjVCzq2abeGcHTqVH");

      expect(await wdilv.balanceOf(user1.address)).to.equal(300n * ONE_DILV);
    });

    it("should reject burn with empty native address", async function () {
      await wdilv.mint(user1.address, 100n * ONE_DILV, TXID_1);
      await expect(
        wdilv.connect(user1).burn(ONE_DILV, "")
      ).to.be.revertedWith("Empty native address");
    });
  });

  describe("Pause / Unpause", function () {
    it("should block mint and burn when paused", async function () {
      await wdilv.mint(user1.address, 100n * ONE_DILV, TXID_1);
      await wdilv.pause();

      await expect(
        wdilv.mint(user1.address, ONE_DILV, TXID_2)
      ).to.be.revertedWithCustomError(wdilv, "EnforcedPause");

      await expect(
        wdilv.connect(user1).burn(ONE_DILV, "D6kuPWxvnbEbGcS4dSjVCzq2abeGcHTqVH")
      ).to.be.revertedWithCustomError(wdilv, "EnforcedPause");
    });

    it("should resume after unpause", async function () {
      await wdilv.pause();
      await wdilv.unpause();
      await wdilv.mint(user1.address, ONE_DILV, TXID_1);
      expect(await wdilv.balanceOf(user1.address)).to.equal(ONE_DILV);
    });
  });
});
