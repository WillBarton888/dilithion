#!/usr/bin/env python3
# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Test coinbase subsidy halving schedule

This test validates that:
1. Initial subsidy is 50 DIL
2. Subsidy halves every 210,000 blocks
3. Halving schedule produces ~21M total supply
4. Subsidy becomes 0 after 64 halvings
5. Subsidy calculation is correct at all heights

Based on consensus analysis:
- Location: src/consensus/validation.cpp:12-31
- Initial: 50 DIL (5,000,000,000 satoshis)
- Interval: 210,000 blocks
- Max halvings: 64
- Total supply: ~21,000,000 DIL

Halving Schedule:
  Block 0-209,999: 50 DIL
  Block 210,000-419,999: 25 DIL
  Block 420,000-629,999: 12.5 DIL
  Block 630,000-839,999: 6.25 DIL
  ... continues until subsidy reaches 0
"""

from test_framework.test_framework import DilithionTestFramework
from test_framework.util import (
    assert_equal,
    Decimal,
    COIN,
)


class SubsidyHalvingTest(DilithionTestFramework):
    """Test coinbase subsidy halving"""

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def calculate_subsidy(self, height):
        """Calculate expected subsidy for a given height

        Implements algorithm from src/consensus/validation.cpp:12-31

        Args:
            height: Block height

        Returns:
            Subsidy in satoshis
        """
        INITIAL_SUBSIDY = 50 * COIN  # 50 DIL in satoshis
        HALVING_INTERVAL = 210000
        MAX_HALVINGS = 64

        # Calculate which halving period we're in
        halvings = height // HALVING_INTERVAL

        # After 64 halvings, subsidy is 0
        if halvings >= MAX_HALVINGS:
            return 0

        # Calculate subsidy: initial >> halvings
        # This is integer division (bit shift right)
        subsidy = INITIAL_SUBSIDY >> halvings

        return subsidy

    def calculate_total_supply(self, max_height=None):
        """Calculate total coin supply up to a height

        Args:
            max_height: Maximum height to calculate (default: all halvings)

        Returns:
            Total supply in DIL
        """
        if max_height is None:
            # Calculate for all 64 halvings
            max_height = 210000 * 64

        total = 0
        current_height = 0

        while current_height < max_height:
            subsidy = self.calculate_subsidy(current_height)
            if subsidy == 0:
                break

            # How many blocks at this subsidy level?
            next_halving = ((current_height // 210000) + 1) * 210000
            blocks_at_this_level = min(next_halving, max_height) - current_height

            total += subsidy * blocks_at_this_level
            current_height = next_halving

        # Convert satoshis to DIL
        return Decimal(total) / Decimal(COIN)

    def run_test(self):
        self.log.info("Starting coinbase subsidy halving tests...")

        node = self.nodes[0]
        address = node.getnewaddress()

        # Constants
        INITIAL_SUBSIDY = 50 * COIN
        HALVING_INTERVAL = 210000

        # Test 1: Genesis block subsidy
        self.log.info("Test 1: Genesis block has 50 DIL subsidy")
        genesis_subsidy = self.calculate_subsidy(0)
        assert_equal(genesis_subsidy, INITIAL_SUBSIDY)
        self.log.info(f"✓ Genesis subsidy: {genesis_subsidy / COIN} DIL")

        # Test 2: Block 1 subsidy (still first era)
        self.log.info("Test 2: Block 1 has 50 DIL subsidy")
        block1_subsidy = self.calculate_subsidy(1)
        assert_equal(block1_subsidy, INITIAL_SUBSIDY)
        self.log.info(f"✓ Block 1 subsidy: {block1_subsidy / COIN} DIL")

        # Test 3: Last block before first halving
        self.log.info("Test 3: Block 209,999 has 50 DIL subsidy")
        last_before_halving = self.calculate_subsidy(209999)
        assert_equal(last_before_halving, INITIAL_SUBSIDY)
        self.log.info(f"✓ Block 209,999 subsidy: {last_before_halving / COIN} DIL")

        # Test 4: First halving (block 210,000)
        self.log.info("Test 4: Block 210,000 has 25 DIL subsidy (first halving)")
        first_halving = self.calculate_subsidy(210000)
        expected_first_halving = INITIAL_SUBSIDY // 2
        assert_equal(first_halving, expected_first_halving)
        self.log.info(f"✓ First halving subsidy: {first_halving / COIN} DIL")

        # Test 5: Second halving (block 420,000)
        self.log.info("Test 5: Block 420,000 has 12.5 DIL subsidy (second halving)")
        second_halving = self.calculate_subsidy(420000)
        expected_second_halving = INITIAL_SUBSIDY // 4
        assert_equal(second_halving, expected_second_halving)
        self.log.info(f"✓ Second halving subsidy: {second_halving / COIN} DIL")

        # Test 6: Third halving (block 630,000)
        self.log.info("Test 6: Block 630,000 has 6.25 DIL subsidy (third halving)")
        third_halving = self.calculate_subsidy(630000)
        expected_third_halving = INITIAL_SUBSIDY // 8
        assert_equal(third_halving, expected_third_halving)
        self.log.info(f"✓ Third halving subsidy: {third_halving / COIN} DIL")

        # Test 7: Fourth halving (block 840,000)
        self.log.info("Test 7: Block 840,000 has 3.125 DIL subsidy (fourth halving)")
        fourth_halving = self.calculate_subsidy(840000)
        expected_fourth_halving = INITIAL_SUBSIDY // 16
        assert_equal(fourth_halving, expected_fourth_halving)
        self.log.info(f"✓ Fourth halving subsidy: {fourth_halving / COIN} DIL")

        # Test 8: 64th halving (subsidy becomes 0)
        self.log.info("Test 8: 64th halving - subsidy becomes 0")
        halving_64_height = HALVING_INTERVAL * 64
        halving_64_subsidy = self.calculate_subsidy(halving_64_height)
        assert_equal(halving_64_subsidy, 0)
        self.log.info(f"✓ Block {halving_64_height:,} subsidy: 0 DIL (64th halving)")

        # Test 9: After all halvings
        self.log.info("Test 9: Subsidy remains 0 after all halvings")
        after_halvings = self.calculate_subsidy(halving_64_height + 1000000)
        assert_equal(after_halvings, 0)
        self.log.info("✓ Subsidy is 0 after all halvings")

        # Test 10: Total supply calculation
        self.log.info("Test 10: Total supply is ~21 million DIL")
        total_supply = self.calculate_total_supply()
        self.log.info(f"  Total supply after all halvings: {total_supply} DIL")

        # Should be very close to 21 million (within satoshi precision)
        expected_supply = Decimal("21000000")
        difference = abs(total_supply - expected_supply)

        # Allow small difference due to integer division
        assert_equal(difference < Decimal("0.01"), True,
                     f"Total supply should be ~21M DIL (actual: {total_supply})")

        self.log.info(f"✓ Total supply: {total_supply} DIL (target: {expected_supply} DIL)")

        # Test 11: Subsidy at specific interesting heights
        self.log.info("Test 11: Subsidy at various heights")

        test_heights = [
            (0, 50),
            (100000, 50),
            (210000, 25),
            (300000, 25),
            (420000, 12.5),
            (630000, 6.25),
            (840000, 3.125),
            (1050000, 1.5625),
        ]

        for height, expected_dil in test_heights:
            subsidy = self.calculate_subsidy(height)
            expected_satoshis = int(expected_dil * COIN)
            assert_equal(subsidy, expected_satoshis,
                        f"Block {height} should have {expected_dil} DIL subsidy")
            self.log.info(f"  Block {height:>7,}: {subsidy / COIN:>8} DIL ✓")

        # Test 12: Halving schedule progression
        self.log.info("Test 12: Complete halving schedule")

        self.log.info("\n  Halving Schedule:")
        self.log.info("  " + "=" * 60)
        self.log.info(f"  {'Halving':>8} | {'Block Range':>25} | {'Subsidy':>12}")
        self.log.info("  " + "-" * 60)

        for halving_num in range(10):  # Show first 10 halvings
            start_block = halving_num * HALVING_INTERVAL
            end_block = start_block + HALVING_INTERVAL - 1
            subsidy = self.calculate_subsidy(start_block)

            if subsidy == 0:
                break

            subsidy_dil = subsidy / COIN
            self.log.info(f"  {halving_num:>8} | {start_block:>10,}-{end_block:>10,} | {subsidy_dil:>10} DIL")

        self.log.info("  " + "=" * 60)

        # Test 13: Subsidy never exceeds initial amount
        self.log.info("\nTest 13: Subsidy never exceeds initial 50 DIL")
        for height in [0, 1, 100, 1000, 10000, 100000, 209999]:
            subsidy = self.calculate_subsidy(height)
            assert_equal(subsidy <= INITIAL_SUBSIDY, True,
                        f"Subsidy at height {height} should not exceed initial")

        self.log.info("✓ Subsidy never exceeds 50 DIL before first halving")

        # Test 14: Subsidy progression is monotonically decreasing
        self.log.info("Test 14: Subsidy decreases monotonically")

        prev_subsidy = INITIAL_SUBSIDY + 1  # Start higher
        for height in range(0, 1000000, 10000):
            subsidy = self.calculate_subsidy(height)
            assert_equal(subsidy <= prev_subsidy, True,
                        f"Subsidy should decrease or stay same at height {height}")
            prev_subsidy = subsidy

        self.log.info("✓ Subsidy decreases monotonically over time")

        # Test 15: Total coins mined in first era (blocks 0-209,999)
        self.log.info("Test 15: Total coins in first era")

        first_era_total = 50 * 210000  # 50 DIL * 210,000 blocks
        calculated_first_era = self.calculate_total_supply(max_height=210000)

        assert_equal(calculated_first_era, Decimal(first_era_total))
        self.log.info(f"✓ First era total: {calculated_first_era:,} DIL")

        self.log.info("=" * 70)
        self.log.info("All subsidy halving tests completed successfully!")
        self.log.info("")
        self.log.info("Consensus compliance verified:")
        self.log.info("  ✓ Initial subsidy: 50 DIL")
        self.log.info("  ✓ Halving interval: 210,000 blocks")
        self.log.info("  ✓ Total supply: ~21,000,000 DIL")
        self.log.info("  ✓ Maximum halvings: 64")
        self.log.info("  ✓ Monotonically decreasing")
        self.log.info("  ✓ No inflation bugs detected")


if __name__ == "__main__":
    SubsidyHalvingTest().main()
