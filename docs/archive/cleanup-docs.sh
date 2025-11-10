#!/bin/bash
# Documentation Cleanup Script
# Organizes all markdown files into proper directory structure

echo "Organizing documentation files..."

# Count files before
before=$(find . -maxdepth 1 -name "*.md" -type f | wc -l)
echo "Found $before markdown files in root directory"

# Session summaries → docs/archive/sessions/
mv WORK-SESSION-*.md docs/archive/sessions/ 2>/dev/null
mv SESSION-*.md docs/archive/sessions/ 2>/dev/null
mv AUTONOMOUS-*.md docs/archive/sessions/ 2>/dev/null
mv STATUS-*.md docs/archive/sessions/ 2>/dev/null
mv WEEK-*-COMPLETE.md docs/archive/sessions/ 2>/dev/null
mv WEEK-*-RESULTS.md docs/archive/sessions/ 2>/dev/null
mv CONTINUE-TOMORROW-*.md docs/archive/sessions/ 2>/dev/null

# Planning documents → docs/archive/planning/
mv *PLAN*.md docs/archive/planning/ 2>/dev/null
mv TODO-*.md docs/archive/planning/ 2>/dev/null
mv *IMPLEMENTATION-PLAN*.md docs/archive/planning/ 2>/dev/null
mv NEXT-STEPS-*.md docs/archive/planning/ 2>/dev/null
mv WEEK-*-ACTION-PLAN.md docs/archive/planning/ 2>/dev/null

# Completion reports → docs/archive/
mv *COMPLETION*.md docs/archive/ 2>/dev/null
mv *COMPLETE*.md docs/archive/ 2>/dev/null
mv PHASE-*-REPORT*.md docs/archive/ 2>/dev/null
mv PATH-*-COMPLETION*.md docs/archive/ 2>/dev/null

# Audit & security reports → docs/security/
mv *AUDIT*.md docs/security/ 2>/dev/null
mv *SECURITY*.md docs/security/ 2>/dev/null
mv COMPREHENSIVE-BLOCKCHAIN-*.md docs/security/ 2>/dev/null
mv *FIXES-*.md docs/security/ 2>/dev/null
mv *REMEDIATION*.md docs/security/ 2>/dev/null
mv *SECURITY-*.md docs/security/ 2>/dev/null
mv THREAT-*.md docs/security/ 2>/dev/null
mv BASH-SECURITY-*.md docs/security/ 2>/dev/null
mv BATCH-SECURITY-*.md docs/security/ 2>/dev/null
mv WALLET-SECURITY-*.md docs/security/ 2>/dev/null

# Deployment & operations → docs/operations/
mv *DEPLOYMENT*.md docs/operations/ 2>/dev/null
mv *SETUP-GUIDE*.md docs/operations/ 2>/dev/null
mv *LAUNCH*.md docs/operations/ 2>/dev/null
mv INFRASTRUCTURE-*.md docs/operations/ 2>/dev/null
mv VPS-*.md docs/operations/ 2>/dev/null
mv DIGITAL-OCEAN-*.md docs/operations/ 2>/dev/null
mv WEBCENTRAL-*.md docs/operations/ 2>/dev/null
mv MAINNET-*.md docs/operations/ 2>/dev/null
mv TESTNET-*.md docs/operations/ 2>/dev/null
mv *NODE-SETUP*.md docs/operations/ 2>/dev/null
mv SEED-NODE-*.md docs/operations/ 2>/dev/null

# Test reports → docs/testing/
mv TEST-*.md docs/testing/ 2>/dev/null
mv *TEST-RESULTS*.md docs/testing/ 2>/dev/null
mv *COVERAGE*.md docs/testing/ 2>/dev/null
mv COMPREHENSIVE-TEST-*.md docs/testing/ 2>/dev/null

# User documentation → docs/user/
mv CLI-WALLET-GUIDE.md docs/user/ 2>/dev/null
mv HOW-TO-*.md docs/user/ 2>/dev/null
mv QUICK-START-*.md docs/user/ 2>/dev/null
mv BEGINNER-*.md docs/user/ 2>/dev/null
mv *WALLET-GUIDE*.md docs/user/ 2>/dev/null
mv RECOMMENDED_WALLET_SETUP.md docs/user/ 2>/dev/null

# Developer documentation → docs/developer/
mv Development-*.md docs/developer/ 2>/dev/null
mv CODE-QUALITY-*.md docs/developer/ 2>/dev/null
mv BITCOIN-*.md docs/developer/ 2>/dev/null
mv *ANALYSIS*.md docs/developer/ 2>/dev/null
mv PERFORMANCE-*.md docs/developer/ 2>/dev/null

# Release & media → docs/archive/
mv RELEASE-*.md docs/archive/ 2>/dev/null
mv *MEDIA-RELEASE*.md docs/archive/ 2>/dev/null
mv *ANNOUNCEMENT*.md docs/archive/ 2>/dev/null
mv GITHUB-*.md docs/archive/ 2>/dev/null
mv UPLOAD-*.md docs/archive/ 2>/dev/null
mv BUILD-BINARY-*.md docs/archive/ 2>/dev/null
mv SOCIAL-MEDIA-*.md docs/archive/ 2>/dev/null
mv DISCORD-*.md docs/archive/ 2>/dev/null

# Miscellaneous historical → docs/archive/
mv *SUMMARY*.md docs/archive/ 2>/dev/null
mv PROJECT-STATUS-*.md docs/archive/ 2>/dev/null
mv INITIAL-ASSESSMENT-*.md docs/archive/ 2>/dev/null
mv ASSESSMENT-*.md docs/archive/ 2>/dev/null
mv PROJECT-COMPREHENSIVE-*.md docs/archive/ 2>/dev/null
mv EXPERT-*.md docs/archive/ 2>/dev/null
mv *TRAINING*.md docs/archive/ 2>/dev/null
mv MESSAGE-*.md docs/archive/ 2>/dev/null
mv INCIDENT-*.md docs/archive/ 2>/dev/null
mv PATH-TO-*.md docs/archive/ 2>/dev/null
mv DILITHION-TO-*.md docs/archive/ 2>/dev/null
mv PRODUCTION-*.md docs/archive/ 2>/dev/null
mv DEFICIENCY-*.md docs/archive/ 2>/dev/null
mv CRITICAL-BUG-*.md docs/archive/ 2>/dev/null
mv WEBSITE-*.md docs/archive/ 2>/dev/null
mv KNOWN-ISSUES.md docs/archive/ 2>/dev/null
mv QUESTIONS-*.md docs/archive/ 2>/dev/null
mv MINING-UI-*.md docs/archive/ 2>/dev/null
mv NETWORK-CAPACITY-*.md docs/developer/ 2>/dev/null
mv FEE-MODEL-*.md docs/developer/ 2>/dev/null

# Implementation summaries → docs/archive/
mv *IMPLEMENTATION-SUMMARY*.md docs/archive/ 2>/dev/null
mv WIZARD_IMPLEMENTATION_SUMMARY.md docs/archive/ 2>/dev/null
mv PASSPHRASE-VALIDATOR-*.md docs/archive/ 2>/dev/null
mv HD-WALLET-IMPLEMENTATION-STATUS.md docs/archive/ 2>/dev/null

# Guides (keep some in root, archive old ones)
mv FRESH-VM-*.md docs/archive/ 2>/dev/null
mv NODE-COMMUNICATION-*.md docs/archive/ 2>/dev/null
mv PUSH-INSTRUCTIONS.md docs/archive/ 2>/dev/null
mv GIT-PUSH-*.md docs/archive/ 2>/dev/null
mv FUZZING-CAMPAIGNS-*.md docs/testing/ 2>/dev/null

# Technical specs (keep active ones, archive historical)
mv CONSENSUS-PARAMETERS-*.md docs/developer/ 2>/dev/null
mv EMISSION-SCHEDULE-*.md docs/developer/ 2>/dev/null
mv BLOCK-TIME-*.md docs/developer/ 2>/dev/null
mv DILITHIUM3-*.md docs/developer/ 2>/dev/null
mv DILITHION-COMPREHENSIVE-*.md docs/archive/ 2>/dev/null

# Project tracking
mv PROJECT-TRACKER.md docs/archive/ 2>/dev/null
mv DAY-*-FINAL-*.md docs/archive/ 2>/dev/null
mv NEXT-SESSION-START.md docs/archive/ 2>/dev/null

# Phase 5 specific
mv PHASE-5.*.md docs/archive/ 2>/dev/null

# Packages verification
mv GITHUB-PACKAGES-*.md docs/archive/ 2>/dev/null

# Count files after
after=$(find . -maxdepth 1 -name "*.md" -type f | wc -l)
moved=$((before - after))

echo "✓ Moved $moved markdown files"
echo "✓ $after files remaining in root (should be <30)"
