const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("WrappedDIL", function () {
  let wdil;
  let owner, user1, user2;

  // 10,000 DIL daily cap
  const DAILY_CAP = 1_000_000_000_000n;
  // 1,000 DIL per-deposit limit
  const MAX_PER_DEPOSIT = 100_000_000_000n;
  // 1 DIL = 10^8
  const ONE_DIL = 100_000_000n;

  const TXID_1 = ethers.id("native-txid-1");
  const TXID_2 = ethers.id("native-txid-2");
  const TXID_3 = ethers.id("native-txid-3");

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();

    const WrappedDIL = await ethers.getContractFactory("WrappedDIL");
    wdil = await WrappedDIL.deploy(DAILY_CAP, MAX_PER_DEPOSIT);
    await wdil.waitForDeployment();
  });

  describe("Deployment", function () {
    it("should have correct name, symbol, and decimals", async function () {
      expect(await wdil.name()).to.equal("Wrapped DIL");
      expect(await wdil.symbol()).to.equal("wDIL");
      expect(await wdil.decimals()).to.equal(8);
    });

    it("should set daily mint cap", async function () {
      expect(await wdil.dailyMintCap()).to.equal(DAILY_CAP);
    });

    it("should set max per deposit", async function () {
      expect(await wdil.maxPerDeposit()).to.equal(MAX_PER_DEPOSIT);
    });

    it("should set owner correctly", async function () {
      expect(await wdil.owner()).to.equal(owner.address);
    });

    it("should start unpaused", async function () {
      expect(await wdil.paused()).to.equal(false);
    });

    it("should start with zero supply", async function () {
      expect(await wdil.totalSupply()).to.equal(0);
    });
  });

  describe("Minting", function () {
    it("should allow owner to mint", async function () {
      const amount = 100n * ONE_DIL; // 100 DIL
      await wdil.mint(user1.address, amount, TXID_1);
      expect(await wdil.balanceOf(user1.address)).to.equal(amount);
    });

    it("should emit BridgeMint event", async function () {
      const amount = 50n * ONE_DIL;
      await expect(wdil.mint(user1.address, amount, TXID_1))
        .to.emit(wdil, "BridgeMint")
        .withArgs(user1.address, amount, TXID_1);
    });

    it("should reject non-owner mint", async function () {
      const amount = 10n * ONE_DIL;
      await expect(
        wdil.connect(user1).mint(user2.address, amount, TXID_1)
      ).to.be.revertedWithCustomError(wdil, "OwnableUnauthorizedAccount");
    });

    it("should reject duplicate nativeTxId (replay protection)", async function () {
      const amount = 10n * ONE_DIL;
      await wdil.mint(user1.address, amount, TXID_1);

      await expect(
        wdil.mint(user1.address, amount, TXID_1)
      ).to.be.revertedWith("Already minted for this txid");
    });

    it("should track minted txids correctly", async function () {
      await wdil.mint(user1.address, 10n * ONE_DIL, TXID_1);
      expect(await wdil.minted(TXID_1)).to.equal(true);
      expect(await wdil.minted(TXID_2)).to.equal(false);
    });

    it("should reject mint exceeding per-deposit limit", async function () {
      const tooMuch = MAX_PER_DEPOSIT + 1n;
      await expect(
        wdil.mint(user1.address, tooMuch, TXID_1)
      ).to.be.revertedWith("Exceeds per-deposit limit");
    });

    it("should allow mint at exactly per-deposit limit", async function () {
      await wdil.mint(user1.address, MAX_PER_DEPOSIT, TXID_1);
      expect(await wdil.balanceOf(user1.address)).to.equal(MAX_PER_DEPOSIT);
    });

    it("should enforce daily mint cap", async function () {
      // Mint up to the cap in chunks
      const chunkSize = MAX_PER_DEPOSIT;
      const numChunks = DAILY_CAP / chunkSize;

      for (let i = 0n; i < numChunks; i++) {
        const txid = ethers.id(`txid-${i}`);
        await wdil.mint(user1.address, chunkSize, txid);
      }

      // Next mint should fail
      const overflowTxid = ethers.id("overflow");
      await expect(
        wdil.mint(user1.address, ONE_DIL, overflowTxid)
      ).to.be.revertedWith("Daily mint cap exceeded");
    });

    it("should reset daily cap after 24 hours", async function () {
      // Mint up to the cap
      const chunkSize = MAX_PER_DEPOSIT;
      const numChunks = DAILY_CAP / chunkSize;

      for (let i = 0n; i < numChunks; i++) {
        const txid = ethers.id(`txid-day1-${i}`);
        await wdil.mint(user1.address, chunkSize, txid);
      }

      // Advance time by 24 hours + 1 second
      await time.increase(86401);

      // Should be able to mint again
      const newTxid = ethers.id("txid-day2-0");
      await wdil.mint(user1.address, ONE_DIL, newTxid);
      expect(await wdil.mintedToday()).to.equal(ONE_DIL);
    });
  });

  describe("Burning", function () {
    beforeEach(async function () {
      // Mint some tokens to user1
      await wdil.mint(user1.address, 100n * ONE_DIL, TXID_1);
    });

    it("should allow anyone to burn their own tokens", async function () {
      const burnAmount = 50n * ONE_DIL;
      await wdil
        .connect(user1)
        .burn(burnAmount, "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq");

      expect(await wdil.balanceOf(user1.address)).to.equal(50n * ONE_DIL);
    });

    it("should emit BridgeBurn event with native address", async function () {
      const burnAmount = 25n * ONE_DIL;
      const nativeAddr = "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq";

      await expect(wdil.connect(user1).burn(burnAmount, nativeAddr))
        .to.emit(wdil, "BridgeBurn")
        .withArgs(user1.address, burnAmount, nativeAddr);
    });

    it("should reject burn with empty native address", async function () {
      await expect(
        wdil.connect(user1).burn(ONE_DIL, "")
      ).to.be.revertedWith("Empty native address");
    });

    it("should reject burn exceeding balance", async function () {
      const tooMuch = 200n * ONE_DIL;
      await expect(
        wdil.connect(user1).burn(tooMuch, "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq")
      ).to.be.revertedWithCustomError(wdil, "ERC20InsufficientBalance");
    });

    it("should reduce total supply after burn", async function () {
      const before = await wdil.totalSupply();
      await wdil
        .connect(user1)
        .burn(30n * ONE_DIL, "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq");
      const after = await wdil.totalSupply();
      expect(before - after).to.equal(30n * ONE_DIL);
    });
  });

  describe("Pause / Unpause", function () {
    it("should allow owner to pause", async function () {
      await wdil.pause();
      expect(await wdil.paused()).to.equal(true);
    });

    it("should block mint when paused", async function () {
      await wdil.pause();
      await expect(
        wdil.mint(user1.address, ONE_DIL, TXID_1)
      ).to.be.revertedWithCustomError(wdil, "EnforcedPause");
    });

    it("should block burn when paused", async function () {
      await wdil.mint(user1.address, 10n * ONE_DIL, TXID_1);
      await wdil.pause();
      await expect(
        wdil.connect(user1).burn(ONE_DIL, "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq")
      ).to.be.revertedWithCustomError(wdil, "EnforcedPause");
    });

    it("should allow unpause and resume operations", async function () {
      await wdil.pause();
      await wdil.unpause();
      await wdil.mint(user1.address, ONE_DIL, TXID_1);
      expect(await wdil.balanceOf(user1.address)).to.equal(ONE_DIL);
    });

    it("should reject non-owner pause", async function () {
      await expect(
        wdil.connect(user1).pause()
      ).to.be.revertedWithCustomError(wdil, "OwnableUnauthorizedAccount");
    });
  });

  describe("Admin functions", function () {
    it("should allow owner to update daily mint cap", async function () {
      const newCap = 500_000_000_000n;
      await expect(wdil.setDailyMintCap(newCap))
        .to.emit(wdil, "DailyMintCapUpdated")
        .withArgs(DAILY_CAP, newCap);
      expect(await wdil.dailyMintCap()).to.equal(newCap);
    });

    it("should allow owner to update max per deposit", async function () {
      const newMax = 50_000_000_000n;
      await expect(wdil.setMaxPerDeposit(newMax))
        .to.emit(wdil, "MaxPerDepositUpdated")
        .withArgs(MAX_PER_DEPOSIT, newMax);
      expect(await wdil.maxPerDeposit()).to.equal(newMax);
    });

    it("should reject non-owner cap update", async function () {
      await expect(
        wdil.connect(user1).setDailyMintCap(0)
      ).to.be.revertedWithCustomError(wdil, "OwnableUnauthorizedAccount");
    });
  });

  describe("ERC-20 standard", function () {
    it("should support transfer", async function () {
      await wdil.mint(user1.address, 100n * ONE_DIL, TXID_1);
      await wdil.connect(user1).transfer(user2.address, 30n * ONE_DIL);
      expect(await wdil.balanceOf(user1.address)).to.equal(70n * ONE_DIL);
      expect(await wdil.balanceOf(user2.address)).to.equal(30n * ONE_DIL);
    });

    it("should support approve and transferFrom", async function () {
      await wdil.mint(user1.address, 100n * ONE_DIL, TXID_1);
      await wdil.connect(user1).approve(user2.address, 50n * ONE_DIL);
      await wdil
        .connect(user2)
        .transferFrom(user1.address, user2.address, 50n * ONE_DIL);
      expect(await wdil.balanceOf(user2.address)).to.equal(50n * ONE_DIL);
    });
  });
});
