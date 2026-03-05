// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title WrappedDIL (wDIL)
 * @notice ERC-20 representation of DIL on Base (Coinbase L2).
 *         Minted by the bridge relayer when DIL is deposited on the native chain.
 *         Burned by users to withdraw DIL back to the native chain.
 *
 * TRUST MODEL: This is a custodial bridge. The owner (bridge operator) controls
 * minting. Users trust the operator not to mint without valid deposits.
 * Upgrade path: migrate ownership to a 3-of-5 Gnosis Safe multisig.
 */
contract WrappedDIL is ERC20, Ownable, Pausable {
    uint256 public dailyMintCap;
    uint256 public mintedToday;
    uint256 public lastMintReset;
    uint256 public maxPerDeposit;

    /// @notice Replay protection: tracks which native txids have been minted
    mapping(bytes32 => bool) public minted;

    event BridgeMint(address indexed to, uint256 amount, bytes32 indexed nativeTxId);
    event BridgeBurn(address indexed from, uint256 amount, string nativeAddress);
    event DailyMintCapUpdated(uint256 oldCap, uint256 newCap);
    event MaxPerDepositUpdated(uint256 oldMax, uint256 newMax);

    /**
     * @param _dailyMintCap Maximum amount that can be minted per 24-hour period (in 8-decimal units)
     * @param _maxPerDeposit Maximum amount per single deposit (beta safety limit)
     */
    constructor(uint256 _dailyMintCap, uint256 _maxPerDeposit)
        ERC20("Wrapped DIL", "wDIL")
        Ownable(msg.sender)
    {
        dailyMintCap = _dailyMintCap;
        maxPerDeposit = _maxPerDeposit;
        lastMintReset = block.timestamp;
    }

    /// @notice DIL uses 8 decimal places (1 DIL = 100,000,000 ions)
    function decimals() public pure override returns (uint8) {
        return 8;
    }

    /**
     * @notice Mint wDIL for a confirmed native chain deposit.
     * @param to Recipient address on Base
     * @param amount Amount in 8-decimal units
     * @param nativeTxId The native DIL chain transaction ID (replay protection)
     */
    function mint(address to, uint256 amount, bytes32 nativeTxId)
        external
        onlyOwner
        whenNotPaused
    {
        require(!minted[nativeTxId], "Already minted for this txid");
        require(amount <= maxPerDeposit, "Exceeds per-deposit limit");

        _resetDailyMint();
        require(mintedToday + amount <= dailyMintCap, "Daily mint cap exceeded");

        minted[nativeTxId] = true;
        mintedToday += amount;
        _mint(to, amount);

        emit BridgeMint(to, amount, nativeTxId);
    }

    /**
     * @notice Burn wDIL to withdraw DIL on the native chain.
     * @param amount Amount to burn (in 8-decimal units)
     * @param nativeAddress DIL address to receive funds (e.g. "D...")
     */
    function burn(uint256 amount, string calldata nativeAddress)
        external
        whenNotPaused
    {
        require(bytes(nativeAddress).length > 0, "Empty native address");
        _burn(msg.sender, amount);
        emit BridgeBurn(msg.sender, amount, nativeAddress);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setDailyMintCap(uint256 _cap) external onlyOwner {
        emit DailyMintCapUpdated(dailyMintCap, _cap);
        dailyMintCap = _cap;
    }

    function setMaxPerDeposit(uint256 _max) external onlyOwner {
        emit MaxPerDepositUpdated(maxPerDeposit, _max);
        maxPerDeposit = _max;
    }

    function _resetDailyMint() internal {
        if (block.timestamp >= lastMintReset + 1 days) {
            mintedToday = 0;
            lastMintReset = block.timestamp;
        }
    }
}
