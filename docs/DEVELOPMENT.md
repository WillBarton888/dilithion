# Development Guide

Daily development workflow and best practices for Dilithion contributors.

---

## Daily Workflow

### 1. Start Your Day

```bash
# Update your local repository
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/my-feature

# Update dependencies
git submodule update --init --recursive
```

### 2. Make Changes

```bash
# Edit files
# Follow coding standards
# Add tests for changes
```

### 3. Test Locally

```bash
# Build
make -j$(nproc)

# Run unit tests
make check

# Run affected functional tests
test/functional/feature_dilithium.py
```

### 4. Commit

```bash
# Stage changes
git add src/key.cpp src/test/dilithium_tests.cpp

# Commit with clear message
git commit -m "Implement Dilithium key generation

- Add CKey::MakeNewKey() implementation
- Use pqcrystals reference implementation
- Add unit tests for key generation
- Validate against NIST test vectors

Closes #42"
```

### 5. Push & PR

```bash
# Push to your fork
git push origin feature/my-feature

# Create pull request on GitHub
# Fill out PR template
# Request reviews
```

---

## Code Standards

### C++ Style

Follow Bitcoin Core standards:
- 4 spaces (no tabs)
- 120 character line limit
- CamelCase for classes
- camelCase for functions
- Type prefixes for member variables

### Commit Messages

```
Brief summary (50 chars)

Detailed explanation (72 char wrap):
- What changed
- Why it changed
- How it was tested

Closes #issue
```

---

## Testing Requirements

Before every commit:
- [ ] Code compiles
- [ ] Unit tests pass
- [ ] New tests added
- [ ] No warnings

Before every PR:
- [ ] Functional tests pass
- [ ] Coverage maintained
- [ ] Documentation updated
- [ ] Code reviewed

---

## Common Tasks

### Add New Feature
1. Design with tests in mind
2. Write failing tests
3. Implement feature
4. Make tests pass
5. Refactor
6. Document

### Fix Bug
1. Write test reproducing bug
2. Verify test fails
3. Fix bug
4. Verify test passes
5. Add to regression suite

### Refactor Code
1. Ensure tests pass before
2. Make changes
3. Ensure tests still pass
4. No behavior changes

---

## Tools

### Build Tools
- **ccache** - Faster rebuilds
- **bear** - Compile commands for IDEs
- **clang-format** - Code formatting

### Analysis Tools
- **valgrind** - Memory leaks
- **AddressSanitizer** - Memory errors
- **UBSan** - Undefined behavior
- **clang-tidy** - Static analysis

### Debugging
- **gdb** - Debugger
- **lldb** - Alternative debugger
- **rr** - Record and replay

---

## Getting Help

- Read documentation first
- Search existing issues
- Ask in GitHub Discussions
- Tag relevant reviewers

---

**Remember:** Write code for humans first, computers second. Clear code > clever code.
