# Phase 1: Cleanup Plan & Procedures

**Date:** 2025-11-10
**Purpose:** Comprehensive project organization and cleanup
**Target:** Professional, audit-ready project structure

---

## Executive Summary

**Current State:** 7/10 (Organizational chaos)
**Target State:** 9/10 (Professional, audit-ready)

**Files to Relocate:** ~200
**Files to Delete:** ~20
**Directories to Create:** 6
**Est. Time:** 2 hours

---

## 1. Cleanup Priorities

### Priority 1: CRITICAL (Security & Space)
- **Delete:** DiscordSetup.exe (115MB - not project-related)
- **Delete:** fuzz_difficulty_campaign.log (1.1GB - old log)
- **Delete:** Large duplicate files with (1), (2), (3) suffixes
- **Relocate:** Build artifacts (.o files) to build/
- **Update:** .gitignore to prevent future pollution

### Priority 2: HIGH (Organization)
- **Relocate:** 150+ session/status docs to docs/archive/
- **Relocate:** 65 log files to logs/
- **Relocate:** 17 .test_utxo_* directories to test/artifacts/
- **Relocate:** Executables to bin/
- **Create:** Proper directory structure

### Priority 3: MEDIUM (Documentation)
- **Consolidate:** Audit reports to docs/security/
- **Consolidate:** Deployment guides to docs/operations/
- **Consolidate:** Test reports to docs/testing/
- **Organize:** User documentation to docs/user/

---

## 2. Detailed Cleanup Actions

### 2.1 Create Directory Structure

```bash
# Create new organizational directories
mkdir -p bin
mkdir -p logs
mkdir -p test/logs
mkdir -p test/artifacts
mkdir -p docs/user
mkdir -p docs/developer
mkdir -p docs/security
mkdir -p docs/operations
mkdir -p docs/testing
mkdir -p docs/planning
mkdir -p docs/archive/sessions
mkdir -p docs/archive/planning
mkdir -p docs/archive/audits
mkdir -p audit  # For this comprehensive audit
```

### 2.2 Delete Non-Project Files

```bash
# Priority 1: Delete large non-project files
rm -f DiscordSetup.exe                    # 115MB Discord installer
rm -f fuzz_difficulty_campaign.log        # 1.1GB old log file

# Delete duplicate release packages
rm -f "dilithion-testnet-v1.0.0-linux-x64 (1).tar.gz"
rm -f "dilithion-testnet-v1.0.0-linux-x64 (2).tar.gz"
rm -f "dilithion-testnet-v1.0.0-macos-x64 (1).tar.gz"
rm -f "dilithion-testnet-v1.0.0-windows-x64 (1).zip"
rm -f "dilithion-testnet-v1.0.0-windows-x64 (2).zip"
rm -f "dilithion-testnet-v1.0.0-windows-x64 (3).zip"

# Delete backup files
rm -f *backup
rm -f dilithion-wallet.backup

# Delete old/superseded scripts
rm -f SETUP-AND-START.bat                 # Keep SETUP-AND-START-FIXED.bat
rm -f START-MINING.bat                    # Keep START-MINING-FIXED.bat
```

### 2.3 Relocate Build Artifacts

```bash
# Move object files to build/
find src -name "*.o" -exec mv {} build/obj/ \;

# Move executables to bin/
mv *.exe bin/ 2>/dev/null || true
mv *.dll bin/ 2>/dev/null || true
mv dilithion-miner bin/ 2>/dev/null || true
mv dilithion-wallet bin/ 2>/dev/null || true
mv check-wallet-balance bin/ 2>/dev/null || true

# Move test artifacts
mv .test_utxo_* test/artifacts/ 2>/dev/null || true
```

### 2.4 Relocate Logs

```bash
# Move all log files to logs/
mv *.log logs/ 2>/dev/null || true

# Exclude important logs (keep in root)
cp logs/README.md . 2>/dev/null || true
```

### 2.5 Reorganize Documentation

**Session Summaries → docs/archive/sessions/**
```bash
mv WORK-SESSION-*.md docs/archive/sessions/
mv SESSION-*.md docs/archive/sessions/
mv AUTONOMOUS-*.md docs/archive/sessions/
```

**Status Reports → docs/archive/sessions/**
```bash
mv STATUS-*.md docs/archive/sessions/
mv WEEK-*-COMPLETE.md docs/archive/sessions/
mv WEEK-*-RESULTS.md docs/archive/sessions/
mv CONTINUE-TOMORROW-*.md docs/archive/sessions/
```

**Planning Documents → docs/archive/planning/**
```bash
mv *PLAN*.md docs/archive/planning/
mv TODO-*.md docs/archive/planning/
mv TOMORROW-*.md docs/archive/planning/
mv NEXT-*.md docs/archive/planning/
mv *IMPLEMENTATION-PLAN*.md docs/archive/planning/
```

**Completion Reports → docs/archive/**
```bash
mv *COMPLETION*.md docs/archive/
mv *COMPLETE*.md docs/archive/
mv PHASE-*-REPORT*.md docs/archive/
```

**Audit Reports → docs/security/**
```bash
mv *AUDIT*.md docs/security/
mv *SECURITY*.md docs/security/
mv COMPREHENSIVE-BLOCKCHAIN-*.md docs/security/
mv *FIXES-*.md docs/security/
mv *REMEDIATION*.md docs/security/
```

**Deployment Guides → docs/operations/**
```bash
mv *DEPLOYMENT*.md docs/operations/
mv *SETUP-GUIDE*.md docs/operations/
mv *LAUNCH*.md docs/operations/
mv INFRASTRUCTURE-*.md docs/operations/
mv VPS-*.md docs/operations/
mv DIGITAL-OCEAN-*.md docs/operations/
mv WEBCENTRAL-*.md docs/operations/
mv MAINNET-*.md docs/operations/
mv TESTNET-*.md docs/operations/
```

**Test Reports → docs/testing/**
```bash
mv TEST-*.md docs/testing/
mv *TEST-RESULTS*.md docs/testing/
mv *COVERAGE*.md docs/testing/
```

**User Documentation → docs/user/**
```bash
mv CLI-WALLET-GUIDE.md docs/user/
mv HOW-TO-*.md docs/user/
mv QUICK-START-*.md docs/user/
mv BEGINNER-*.md docs/user/
```

**Developer Documentation → docs/developer/**
```bash
mv Development-*.md docs/developer/
mv CODE-QUALITY-*.md docs/developer/
mv BITCOIN-*.md docs/developer/
```

### 2.6 Keep in Root (20-30 files)

**Essential Files (Keep in Root):**
- README.md
- CHANGELOG.md
- LICENSE
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- SECURITY.md
- Makefile
- .gitignore
- .gitmodules

**Core Documentation (Keep in Root):**
- WHITEPAPER.md
- TEAM.md
- KNOWN-ISSUES.md
- PROJECT-STATUS.md (current)

**Active Work Trackers (Keep in Root):**
- NEXT-SESSION-START.md (if actively used)
- PROJECT-TRACKER.md (if actively used)

**Configuration Examples (Keep in Root):**
- contrib/dilithion.conf.example

**Demos (Keep in Root):**
- demo_wallet_simple.py
- demo_wallet_interface.py

---

## 3. Automated Cleanup Script

### cleanup-project.sh

```bash
#!/bin/bash
# Dilithion Project Cleanup Script
# Date: 2025-11-10
# Purpose: Organize project for security audit

set -e  # Exit on error

echo "═══════════════════════════════════════════"
echo "  Dilithion Project Cleanup Script"
echo "  Preparing for CertiK-Level Security Audit"
echo "═══════════════════════════════════════════"
echo ""

# Backup before cleanup
echo "[1/10] Creating backup..."
tar -czf "../dilithion-backup-pre-cleanup-$(date +%Y%m%d-%H%M%S).tar.gz" \
    --exclude='.git' \
    --exclude='build' \
    --exclude='node_modules' \
    --exclude='releases' \
    .
echo "✓ Backup created"

# Create directory structure
echo "[2/10] Creating directory structure..."
mkdir -p bin logs test/logs test/artifacts
mkdir -p docs/user docs/developer docs/security docs/operations docs/testing docs/planning
mkdir -p docs/archive/sessions docs/archive/planning docs/archive/audits
mkdir -p audit
echo "✓ Directories created"

# Delete non-project files
echo "[3/10] Deleting non-project files..."
rm -f DiscordSetup.exe 2>/dev/null && echo "  - Deleted DiscordSetup.exe (115MB)" || true
rm -f fuzz_difficulty_campaign.log 2>/dev/null && echo "  - Deleted old fuzzing log (1.1GB)" || true

# Delete duplicate release packages
echo "[4/10] Deleting duplicate release packages..."
find . -maxdepth 1 -name "*\(1\).*" -o -name "*\(2\).*" -o -name "*\(3\).*" | while read file; do
    rm -f "$file" && echo "  - Deleted: $file"
done

# Delete backup files
rm -f *.backup 2>/dev/null || true
echo "✓ Non-project files deleted"

# Relocate build artifacts
echo "[5/10] Relocating build artifacts..."
find src -name "*.o" -exec mv {} build/obj/ \; 2>/dev/null || true

# Move executables
echo "[6/10] Relocating executables to bin/..."
mv *.exe bin/ 2>/dev/null || true
mv *.dll bin/ 2>/dev/null || true
mv dilithion-miner bin/ 2>/dev/null || true
mv dilithion-wallet bin/ 2>/dev/null || true
mv check-wallet-balance bin/ 2>/dev/null || true
echo "✓ Executables relocated"

# Move logs
echo "[7/10] Relocating log files..."
count=$(find . -maxdepth 1 -name "*.log" | wc -l)
mv *.log logs/ 2>/dev/null || true
echo "✓ Moved $count log files"

# Move test artifacts
echo "[8/10] Relocating test artifacts..."
mv .test_utxo_* test/artifacts/ 2>/dev/null || true
echo "✓ Test artifacts relocated"

# Reorganize documentation
echo "[9/10] Reorganizing documentation..."

# Session summaries
mv WORK-SESSION-*.md docs/archive/sessions/ 2>/dev/null || true
mv SESSION-*.md docs/archive/sessions/ 2>/dev/null || true
mv AUTONOMOUS-*.md docs/archive/sessions/ 2>/dev/null || true
mv STATUS-*.md docs/archive/sessions/ 2>/dev/null || true
mv WEEK-*-COMPLETE.md docs/archive/sessions/ 2>/dev/null || true
mv WEEK-*-RESULTS.md docs/archive/sessions/ 2>/dev/null || true
mv CONTINUE-TOMORROW-*.md docs/archive/sessions/ 2>/dev/null || true

# Planning documents
mv *PLAN*.md docs/archive/planning/ 2>/dev/null || true
mv TODO-*.md docs/archive/planning/ 2>/dev/null || true
mv *IMPLEMENTATION-PLAN*.md docs/archive/planning/ 2>/dev/null || true

# Completion reports
mv *COMPLETION*.md docs/archive/ 2>/dev/null || true
mv *COMPLETE*.md docs/archive/ 2>/dev/null || true
mv PHASE-*-REPORT*.md docs/archive/ 2>/dev/null || true

# Audit reports
mv *AUDIT*.md docs/security/ 2>/dev/null || true
mv *SECURITY*.md docs/security/ 2>/dev/null || true
mv COMPREHENSIVE-BLOCKCHAIN-*.md docs/security/ 2>/dev/null || true
mv *FIXES-*.md docs/security/ 2>/dev/null || true
mv *REMEDIATION*.md docs/security/ 2>/dev/null || true

# Deployment guides
mv *DEPLOYMENT*.md docs/operations/ 2>/dev/null || true
mv *SETUP-GUIDE*.md docs/operations/ 2>/dev/null || true
mv *LAUNCH*.md docs/operations/ 2>/dev/null || true
mv INFRASTRUCTURE-*.md docs/operations/ 2>/dev/null || true
mv VPS-*.md docs/operations/ 2>/dev/null || true
mv DIGITAL-OCEAN-*.md docs/operations/ 2>/dev/null || true
mv WEBCENTRAL-*.md docs/operations/ 2>/dev/null || true
mv MAINNET-*.md docs/operations/ 2>/dev/null || true
mv TESTNET-*.md docs/operations/ 2>/dev/null || true

# Test reports
mv TEST-*.md docs/testing/ 2>/dev/null || true
mv *TEST-RESULTS*.md docs/testing/ 2>/dev/null || true
mv *COVERAGE*.md docs/testing/ 2>/dev/null || true

# User documentation
mv CLI-WALLET-GUIDE.md docs/user/ 2>/dev/null || true
mv HOW-TO-*.md docs/user/ 2>/dev/null || true
mv QUICK-START-*.md docs/user/ 2>/dev/null || true
mv BEGINNER-*.md docs/user/ 2>/dev/null || true

# Developer documentation
mv Development-*.md docs/developer/ 2>/dev/null || true
mv CODE-QUALITY-*.md docs/developer/ 2>/dev/null || true
mv BITCOIN-*.md docs/developer/ 2>/dev/null || true

echo "✓ Documentation reorganized"

# Generate documentation index
echo "[10/10] Generating documentation index..."
cat > docs/README.md <<'EOF'
# Dilithion Documentation

This directory contains all project documentation, organized by category.

## Directory Structure

- **user/** - End-user guides and tutorials
- **developer/** - Developer documentation and contribution guides
- **security/** - Security audits, threat models, and security guides
- **operations/** - Deployment, infrastructure, and operational guides
- **testing/** - Test reports, coverage analysis, and testing guides
- **planning/** - Project planning and roadmaps (archived)
- **archive/** - Historical documentation
  - sessions/ - Development session summaries
  - planning/ - Historical planning documents
  - audits/ - Previous audit reports

## Quick Links

### For Users
- [Wallet Setup Guide](user/CLI-WALLET-GUIDE.md)
- [Quick Start](user/QUICK-START-*.md)
- [How-To Guides](user/HOW-TO-*.md)

### For Developers
- [Development Guide](../README.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [Code Quality Standards](developer/CODE-QUALITY-*.md)

### For Operations
- [Deployment Guide](operations/*DEPLOYMENT*.md)
- [Mainnet Setup](operations/MAINNET-*.md)
- [Infrastructure Guide](operations/INFRASTRUCTURE-*.md)

### Security
- [Security Policy](../SECURITY.md)
- [Security Audits](security/*AUDIT*.md)
- [Security Fixes](security/*FIXES*.md)

## Navigation

All active documentation is organized in this directory. For current project status, see [PROJECT-STATUS.md](../PROJECT-STATUS.md) in the root directory.
EOF

echo "✓ Documentation index created"

# Display summary
echo ""
echo "═══════════════════════════════════════════"
echo "  Cleanup Complete!"
echo "═══════════════════════════════════════════"
echo ""
echo "Summary:"
echo "  - Non-project files deleted"
echo "  - Build artifacts relocated to build/"
echo "  - Executables moved to bin/"
echo "  - Logs moved to logs/"
echo "  - Test artifacts moved to test/artifacts/"
echo "  - Documentation organized by category"
echo "  - Created docs/README.md index"
echo ""
echo "Next steps:"
echo "  1. Review root directory (should have <30 files)"
echo "  2. Verify documentation organization"
echo "  3. Update .gitignore"
echo "  4. Commit cleanup changes"
echo ""

# Count files in root
root_files=$(find . -maxdepth 1 -type f | wc -l)
echo "Root directory file count: $root_files"
if [ $root_files -lt 30 ]; then
    echo "✓ Root directory clean (target: <30 files)"
else
    echo "⚠ Root directory needs more cleanup ($root_files files)"
fi
```

---

## 4. Enhanced .gitignore

### Add to .gitignore:

```gitignore
# ═══════════════════════════════════════
#  Dilithion Build & Runtime Artifacts
# ═══════════════════════════════════════

# Build artifacts
*.o
*.obj
*.exe
*.dll
*.so
*.dylib
*.a
build/
bin/
!bin/.gitkeep

# Test artifacts
.test_*
test/artifacts/
test/logs/
*.test
!test/

# Logs
*.log
logs/
!logs/.gitkeep

# ═══════════════════════════════════════
#  Large Files & Temporary
# ═══════════════════════════════════════

# Large installer files
*Setup.exe
*.iso
*.dmg

# Backup files
*.backup
*.bak
*~

# Temporary files
*.tmp
*.temp
*.swp
*.swo

# ═══════════════════════════════════════
#  Editor & IDE
# ═══════════════════════════════════════

# VS Code
.vscode/
*.code-workspace

# Visual Studio
.vs/
*.vcxproj.user
*.suo
*.user

# JetBrains
.idea/
*.iml

# Vim
*.swp
*.swo
*~

# Emacs
*~
\#*\#

# ═══════════════════════════════════════
#  OS Files
# ═══════════════════════════════════════

# macOS
.DS_Store
.AppleDouble
.LSOverride
._*

# Windows
Thumbs.db
ehthumbs.db
Desktop.ini
$RECYCLE.BIN/

# Linux
*~

# ═══════════════════════════════════════
#  Coverage & Analysis
# ═══════════════════════════════════════

# Code coverage
*.gcda
*.gcno
*.gcov
coverage/
htmlcov/
*.coverage
.coverage.*

# Static analysis
cppcheck_results/
scan-build-results/

# ═══════════════════════════════════════
#  Fuzzing
# ═══════════════════════════════════════

# Fuzzing artifacts
fuzz_corpus/
crashes/
hangs/
*.profdata
fuzz-*.log
*-fuzzer

# Corpus backups (keep manifests)
corpus_backups/*/corpus_*
!corpus_backups/*/manifest.json

# ═══════════════════════════════════════
#  Blockchain Data
# ═══════════════════════════════════════

# Blockchain storage (for development)
.dilithion-testnet/blocks/
.dilithion-testnet/chainstate/
.dilithion-mainnet/blocks/
.dilithion-mainnet/chainstate/

# ═══════════════════════════════════════
#  Dependencies
# ═══════════════════════════════════════

# Python
venv/
__pycache__/
*.pyc
*.pyo
*.egg-info/

# Node.js
node_modules/
npm-debug.log*

# ═══════════════════════════════════════
#  Build Systems
# ═══════════════════════════════════════

# CMake
CMakeCache.txt
CMakeFiles/
cmake_install.cmake
Makefile.bak

# Autotools
*.la
*.lo
.deps/
.libs/
autom4te.cache/

# ═══════════════════════════════════════
#  Package Files
# ═══════════════════════════════════════

# Archives (except in releases/)
*.tar.gz
*.tar.bz2
*.tar.xz
*.zip
*.7z
!releases/*.tar.gz
!releases/*.zip

# Duplicate suffixes
*\(1\).*
*\(2\).*
*\(3\).*

# ═══════════════════════════════════════
#  Documentation
# ═══════════════════════════════════════

# Generated documentation
doxygen_output/
html/
latex/

# PDF output (keep final versions)
*.pdf
!docs/*.pdf
!WHITEPAPER.pdf

# ═══════════════════════════════════════
#  Security & Secrets
# ═══════════════════════════════════════

# Wallet files (NEVER commit!)
wallet.dat
wallet.dat.bak
*.wallet

# Private keys
*.key
*.pem
id_rsa*

# Configuration with secrets
dilithion.conf
!dilithion.conf.example

# Environment variables
.env
.env.local

# ═══════════════════════════════════════
#  CI/CD
# ═══════════════════════════════════════

# CircleCI
.circleci/config.yml.bak

# Travis
.travis.yml.bak
```

---

## 5. Post-Cleanup Verification

### 5.1 Verification Checklist

After running cleanup script:

- [ ] Root directory has < 30 files
- [ ] All .log files in logs/
- [ ] All .o files in build/
- [ ] All executables in bin/
- [ ] All test artifacts in test/artifacts/
- [ ] Session docs in docs/archive/sessions/
- [ ] Planning docs in docs/archive/planning/
- [ ] Audit reports in docs/security/
- [ ] Deployment guides in docs/operations/
- [ ] Test reports in docs/testing/
- [ ] User guides in docs/user/
- [ ] Developer docs in docs/developer/
- [ ] docs/README.md created
- [ ] .gitignore updated
- [ ] No DiscordSetup.exe
- [ ] No large .log files in root
- [ ] No duplicate release packages

### 5.2 Verification Commands

```bash
# Count files in root (should be <30)
find . -maxdepth 1 -type f | wc -l

# Check for large files (>10MB) in root
find . -maxdepth 1 -type f -size +10M -ls

# Check for .o files in src/ (should be 0)
find src -name "*.o" | wc -l

# Check for .log files in root (should be 0)
find . -maxdepth 1 -name "*.log" | wc -l

# Check for test artifacts in root (should be 0)
find . -maxdepth 1 -name ".test_*" | wc -l

# Verify directory structure
ls -la docs/
ls -la bin/
ls -la logs/
ls -la test/
ls -la audit/
```

### 5.3 Git Status Check

```bash
# Should show clean working tree or organized changes
git status

# Review changes before committing
git diff --stat
```

---

## 6. Commit Strategy

### 6.1 Commit Message Template

```
chore: Comprehensive project cleanup for security audit preparation

Reorganized project structure to professional audit-ready state.

## Changes Made:

### Deleted:
- DiscordSetup.exe (115MB - not project-related)
- fuzz_difficulty_campaign.log (1.1GB - old log)
- Duplicate release packages (7 files, ~17.5MB)
- Backup files (*.backup)
- Old script versions (-FIXED variants kept)

### Relocated:
- 150+ session/status docs → docs/archive/sessions/
- 65 log files → logs/
- 17 test artifact dirs → test/artifacts/
- Build artifacts (.o files) → build/
- Executables → bin/
- Audit reports → docs/security/
- Deployment guides → docs/operations/
- Test reports → docs/testing/
- User guides → docs/user/
- Developer docs → docs/developer/

### Created:
- bin/, logs/, test/artifacts/ directories
- docs/user/, docs/developer/, docs/security/, docs/operations/
- docs/testing/, docs/planning/ directories
- docs/README.md (documentation index)
- Enhanced .gitignore with comprehensive patterns

## Results:

**Before:**
- Root directory: 211 markdown files, 65 logs, 17 test dirs
- Build artifacts scattered in src/
- Large non-project files (1.2GB total)
- Unclear file organization

**After:**
- Root directory: <30 essential files
- All artifacts properly organized
- Clean, navigable structure
- Professional presentation

**Audit Readiness:** 7/10 → 9/10

Generated with Claude Code (https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## 7. Rollback Plan

### If Cleanup Causes Issues:

```bash
# Extract backup created at step 1
cd ..
tar -xzf dilithion-backup-pre-cleanup-*.tar.gz

# Or use git (if committed)
git reset --hard HEAD~1
```

---

## 8. Timeline

**Phase 2 Execution:**

| Step | Task | Time |
|------|------|------|
| 1 | Create backup | 5 min |
| 2 | Run cleanup script | 15 min |
| 3 | Verify organization | 10 min |
| 4 | Update .gitignore | 5 min |
| 5 | Manual review | 20 min |
| 6 | Git commit | 5 min |
| 7 | Final verification | 10 min |
| 8 | Documentation | 10 min |
| **Total** | | **80 min** |

---

## 9. Success Criteria

Phase 2 is successful when:

1. ✅ Root directory < 30 files
2. ✅ All build artifacts in build/
3. ✅ All logs in logs/
4. ✅ All executables in bin/
5. ✅ All test artifacts in test/artifacts/
6. ✅ Documentation organized and navigable
7. ✅ docs/README.md provides clear navigation
8. ✅ .gitignore prevents future pollution
9. ✅ No non-project files (DiscordSetup.exe, etc.)
10. ✅ Git history clean (single cleanup commit)

---

## 10. Next Phase Preview

**After Phase 2 Cleanup:**

Proceed to Phase 3: Core Cryptography Review
- Line-by-line review of src/crypto/
- Verify test vectors
- Check for timing side-channels
- Memory safety analysis
- Randomness quality assessment

---

**Plan Status:** ✅ COMPLETE
**Ready for Execution:** YES
**Estimated Time:** 1.5 hours
**Risk Level:** LOW (full backup created)
