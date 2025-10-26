# Static Analysis and Code Quality Setup

**Version:** 1.0.0
**Date:** October 25, 2025
**Purpose:** Guide for setting up and running code quality tools

---

## Table of Contents

1. [Overview](#overview)
2. [Tool Installation](#tool-installation)
3. [cppcheck (Static Analysis)](#cppcheck-static-analysis)
4. [clang-tidy (Linter)](#clang-tidy-linter)
5. [Valgrind (Memory Analysis)](#valgrind-memory-analysis)
6. [Code Coverage](#code-coverage)
7. [Makefile Integration](#makefile-integration)
8. [CI/CD Integration](#cicd-integration)

---

## Overview

Static analysis and code quality tools help maintain the 10/10 code quality standard by:

- Detecting potential bugs before runtime
- Enforcing coding standards
- Finding memory leaks
- Measuring test coverage
- Improving code maintainability

---

## Tool Installation

### Ubuntu/Debian

```bash
# Update package list
sudo apt-get update

# Install static analysis tools
sudo apt-get install -y \
    cppcheck \
    clang-tidy \
    clang-tools \
    valgrind \
    lcov \
    gcov

# Verify installations
cppcheck --version
clang-tidy --version
valgrind --version
lcov --version
```

### Fedora/RHEL/CentOS

```bash
sudo dnf install -y \
    cppcheck \
    clang-tools-extra \
    valgrind \
    lcov

cppcheck --version
clang-tidy --version
valgrind --version
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install cppcheck
brew install llvm  # Includes clang-tidy
brew install valgrind  # May not work on Apple Silicon

# Add LLVM to PATH
export PATH="/usr/local/opt/llvm/bin:$PATH"

clang-tidy --version
cppcheck --version
```

### Windows (WSL recommended)

```powershell
# Install WSL2 first
wsl --install

# Then follow Ubuntu instructions inside WSL
```

---

## cppcheck (Static Analysis)

### Basic Usage

```bash
# Analyze entire src directory
cppcheck src/

# Enable all checks
cppcheck --enable=all src/

# Specific error types
cppcheck --enable=warning,style,performance,portability src/

# Suppress specific warnings
cppcheck --enable=all --suppress=missingInclude src/

# Output to file
cppcheck --enable=all src/ 2> cppcheck-report.txt
```

### Recommended Configuration

```bash
# Create .cppcheck config
cat > .cppcheck <<EOF
# Suppressions
missingInclude
unusedFunction

# Include paths
-I src
-I depends/randomx/src
-I depends/dilithium/ref
EOF

# Run with config
cppcheck --enable=all --suppressions-list=.cppcheck src/
```

### Common Issues and Fixes

#### Issue: Missing Includes

```
(information) Cppcheck cannot find all the include files
```

**Fix**: Add include paths
```bash
cppcheck -I src -I depends/randomx/src src/
```

#### Issue: Too Many False Positives

**Fix**: Create suppressions file
```bash
cat > cppcheck-suppressions.txt <<EOF
missingInclude
unmatchedSuppression
EOF

cppcheck --suppressions-list=cppcheck-suppressions.txt src/
```

### Expected Results

For Dilithion project, aim for:
- **0 errors**
- **0 warnings** (or document why each is acceptable)
- **Minimal style issues**

---

## clang-tidy (Linter)

### Basic Usage

```bash
# Analyze single file
clang-tidy src/wallet/wallet.cpp -- -std=c++17 -I src

# Analyze all source files
find src -name "*.cpp" -exec clang-tidy {} -- -std=c++17 -I src \;

# With compile database (recommended)
# First generate compile_commands.json:
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .

# Then run clang-tidy
clang-tidy src/wallet/wallet.cpp
```

### Configuration File

Create `.clang-tidy` in project root:

```yaml
---
Checks: >
  -*,
  bugprone-*,
  cert-*,
  clang-analyzer-*,
  cppcoreguidelines-*,
  modernize-*,
  performance-*,
  readability-*,
  -modernize-use-trailing-return-type,
  -readability-magic-numbers,
  -cppcoreguidelines-avoid-magic-numbers

WarningsAsErrors: ''
HeaderFilterRegex: 'src/.*\.h$'
FormatStyle: 'file'

CheckOptions:
  - key: readability-identifier-naming.ClassCase
    value: CamelCase
  - key: readability-identifier-naming.FunctionCase
    value: CamelCase
  - key: readability-identifier-naming.VariableCase
    value: camelBack
  - key: readability-identifier-naming.ConstantCase
    value: UPPER_CASE
```

### Running with Config

```bash
# Run with .clang-tidy config
clang-tidy src/wallet/wallet.cpp

# Auto-fix issues (use with caution!)
clang-tidy -fix src/wallet/wallet.cpp

# Check specific checks only
clang-tidy -checks='performance-*' src/wallet/wallet.cpp
```

### Common Checks

| Check | Purpose | Action |
|-------|---------|--------|
| `bugprone-*` | Detect likely bugs | Fix immediately |
| `performance-*` | Performance issues | Review and optimize |
| `modernize-*` | Use modern C++ | Update when safe |
| `readability-*` | Code clarity | Improve readability |

---

## Valgrind (Memory Analysis)

### Memory Leak Detection

```bash
# Basic leak check
valgrind --leak-check=full ./dilithion-node

# More detailed output
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         --verbose \
         --log-file=valgrind-out.txt \
         ./dilithion-node

# For tests
valgrind --leak-check=full ./wallet_tests
```

### Interpreting Results

#### No Leaks (Good!)
```
HEAP SUMMARY:
    in use at exit: 0 bytes in 0 blocks
  total heap usage: 1,234 allocs, 1,234 frees

LEAK SUMMARY:
    definitely lost: 0 bytes in 0 blocks
    indirectly lost: 0 bytes in 0 blocks
```

#### Memory Leak (Bad!)
```
LEAK SUMMARY:
    definitely lost: 1,024 bytes in 1 blocks
    indirectly lost: 0 bytes in 0 blocks
```

**Action**: Fix the leak by ensuring all `new` has matching `delete`, all `malloc` has `free`

### Common Issues

#### Issue: Uninitialized Values

```
Conditional jump or move depends on uninitialised value(s)
```

**Fix**: Initialize all variables
```cpp
// Bad
int value;
if (value > 0) { ... }

// Good
int value = 0;
if (value > 0) { ... }
```

#### Issue: Invalid Read/Write

```
Invalid read of size 4
```

**Fix**: Check array bounds, pointer validity

---

## Code Coverage

### Using gcov/lcov

#### 1. Compile with Coverage Flags

```bash
# Modify Makefile or compile manually
CXXFLAGS := -std=c++17 -Wall -Wextra -O0 -g --coverage

# Rebuild
make clean
make tests
```

#### 2. Run Tests

```bash
# Run all tests
./phase1_test
./wallet_tests
./wallet_encryption_integration_tests
./wallet_persistence_tests
# ... etc
```

#### 3. Generate Coverage Report

```bash
# Generate .gcov files
gcov src/**/*.cpp

# Create HTML report with lcov
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' 'depends/*' 'test/*' --output-file coverage-filtered.info
genhtml coverage-filtered.info --output-directory coverage-report

# View report
firefox coverage-report/index.html
```

### Coverage Goals

| Category | Target | Current |
|----------|--------|---------|
| Line Coverage | 80%+ | TBD |
| Function Coverage | 90%+ | TBD |
| Branch Coverage | 70%+ | TBD |

### Improving Coverage

```bash
# Find uncovered lines
lcov --list coverage-filtered.info | grep "0%"

# Write tests for uncovered code
# Add to src/test/
```

---

## Makefile Integration

Add these targets to `Makefile`:

```makefile
# ============================================================================
# Code Quality Targets
# ============================================================================

.PHONY: analyze lint memcheck coverage

# Static analysis with cppcheck
analyze:
	@echo "$(COLOR_YELLOW)Running static analysis...$(COLOR_RESET)"
	@cppcheck --enable=all \
		--suppress=missingInclude \
		--suppress=unusedFunction \
		-I src \
		-I depends/randomx/src \
		-I depends/dilithium/ref \
		src/ 2> cppcheck-report.txt
	@cat cppcheck-report.txt
	@echo "$(COLOR_GREEN)✓ Analysis complete (see cppcheck-report.txt)$(COLOR_RESET)"

# Linting with clang-tidy
lint:
	@echo "$(COLOR_YELLOW)Running linter...$(COLOR_RESET)"
	@find src -name "*.cpp" -not -path "*/test/*" | while read file; do \
		echo "Checking $$file..."; \
		clang-tidy $$file -- -std=c++17 -I src || true; \
	done
	@echo "$(COLOR_GREEN)✓ Linting complete$(COLOR_RESET)"

# Memory leak detection
memcheck: tests
	@echo "$(COLOR_YELLOW)Running memory leak detection...$(COLOR_RESET)"
	@valgrind --leak-check=full --show-leak-kinds=all \
		--log-file=valgrind-phase1.txt ./phase1_test
	@valgrind --leak-check=full --show-leak-kinds=all \
		--log-file=valgrind-wallet.txt ./wallet_tests
	@echo "$(COLOR_GREEN)✓ Memory check complete$(COLOR_RESET)"

# Code coverage
coverage:
	@echo "$(COLOR_YELLOW)Building with coverage...$(COLOR_RESET)"
	@$(MAKE) clean
	@CXXFLAGS="$(CXXFLAGS) --coverage" $(MAKE) tests
	@echo "$(COLOR_YELLOW)Running tests...$(COLOR_RESET)"
	@./phase1_test
	@./wallet_tests
	@./crypter_tests
	@./wallet_encryption_integration_tests
	@echo "$(COLOR_YELLOW)Generating coverage report...$(COLOR_RESET)"
	@lcov --capture --directory . --output-file coverage.info
	@lcov --remove coverage.info '/usr/*' 'depends/*' 'src/test/*' --output-file coverage-filtered.info
	@genhtml coverage-filtered.info --output-directory coverage-report
	@echo "$(COLOR_GREEN)✓ Coverage report: coverage-report/index.html$(COLOR_RESET)"

# Run all quality checks
quality: analyze lint memcheck coverage
	@echo "$(COLOR_GREEN)✓ All quality checks complete$(COLOR_RESET)"
```

### Usage

```bash
# Run static analysis
make analyze

# Run linter
make lint

# Check for memory leaks
make memcheck

# Generate coverage report
make coverage

# Run all checks
make quality
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/quality.yml`:

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  static-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install tools
        run: |
          sudo apt-get update
          sudo apt-get install -y cppcheck clang-tidy

      - name: Run cppcheck
        run: |
          cppcheck --enable=all --suppress=missingInclude \
            -I src -I depends/randomx/src \
            src/ 2> cppcheck-report.txt
          cat cppcheck-report.txt

      - name: Run clang-tidy
        run: |
          find src -name "*.cpp" | xargs clang-tidy \
            -- -std=c++17 -I src

      - name: Upload reports
        uses: actions/upload-artifact@v2
        with:
          name: analysis-reports
          path: cppcheck-report.txt

  memory-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install valgrind
        run: sudo apt-get install -y valgrind

      - name: Build tests
        run: make tests

      - name: Run valgrind
        run: |
          valgrind --leak-check=full ./phase1_test
          valgrind --leak-check=full ./wallet_tests
```

---

## Best Practices

### 1. Run Before Commits

```bash
# Pre-commit hook
cat > .git/hooks/pre-commit <<EOF
#!/bin/bash
make analyze
if [ $? -ne 0 ]; then
    echo "Static analysis failed. Commit aborted."
    exit 1
fi
EOF

chmod +x .git/hooks/pre-commit
```

### 2. Fix Issues Promptly

- **Errors**: Fix immediately
- **Warnings**: Fix before merge
- **Style**: Fix during refactoring

### 3. Document Exceptions

If a warning is a false positive:

```cpp
// cppcheck-suppress uninitvar
int value;  // Intentionally uninitialized, set by external function
```

### 4. Regular Review

- **Weekly**: Run full analysis
- **Monthly**: Review coverage trends
- **Release**: Zero warnings policy

---

## Troubleshooting

### cppcheck: Command Not Found

```bash
# Check installation
which cppcheck

# Reinstall if needed
sudo apt-get install --reinstall cppcheck
```

### clang-tidy: Too Slow

```bash
# Use parallel execution
find src -name "*.cpp" | xargs -P 4 -I {} clang-tidy {} -- -std=c++17 -I src
```

### Valgrind: Still Reachable

"Still reachable" memory is usually not a problem (allocated but not freed at exit). Focus on "definitely lost" and "indirectly lost".

---

## Summary

Regular use of these tools ensures:

- **Bug-free code**: Static analysis catches issues early
- **Memory safety**: Valgrind prevents leaks
- **Code quality**: Linters enforce standards
- **Test coverage**: Coverage reports identify gaps
- **Professional quality**: 10/10 standard maintained

**Recommended workflow:**

1. **Before commit**: `make analyze`
2. **Before PR**: `make quality`
3. **Before release**: Full analysis + manual review

---

**Last Updated:** October 25, 2025
**Version:** 1.0.0
