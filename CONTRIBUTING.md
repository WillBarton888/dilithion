# Contributing to Dilithion

Thank you for your interest in contributing to Dilithion! This document provides guidelines for contributing to the project.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Process](#development-process)
4. [Code Standards](#code-standards)
5. [Testing Requirements](#testing-requirements)
6. [Pull Request Process](#pull-request-process)
7. [Areas of Contribution](#areas-of-contribution)

---

## Code of Conduct

### Our Principles

1. **Technical Excellence:** We prioritize correctness and security over speed
2. **Transparency:** All development happens in public
3. **Respect:** Treat all contributors professionally
4. **Collaboration:** Share knowledge and help others learn

### Expected Behavior

- Be professional and respectful in all interactions
- Focus on technical merit, not personal preferences
- Provide constructive feedback
- Accept constructive criticism gracefully
- Help newcomers learn and contribute

### Unacceptable Behavior

- Personal attacks or harassment
- Trolling or inflammatory comments
- Publishing others' private information
- Promoting scams or get-rich-quick schemes
- Price speculation or market manipulation

---

## Getting Started

### Prerequisites

Before contributing, you should:

1. **Read the documentation:**
   - [README.md](README.md)
   - [Technical Specification](docs/technical-specification.md)
   - [Implementation Roadmap](docs/implementation-roadmap.md)

2. **Set up your environment:**
   - Follow [SETUP.md](docs/SETUP.md)
   - Compile Bitcoin Core successfully
   - Pass all tests

3. **Understand the technology:**
   - Bitcoin Core architecture
   - CRYSTALS-Dilithium signature scheme
   - Post-quantum cryptography basics

### Not Accepting Contributions Yet

**⚠️ Important:** We are currently in Foundation Phase (Month 0-3) and **not yet accepting external contributions**.

**We will open for contributions after:**
- Proof-of-concept is complete
- Core cryptographic implementation is functional
- Testing framework is established
- Contribution workflows are defined

**Expected Timeline:** Month 4-6 (early 2026)

---

## Development Process

### Current Phase: Foundation (Closed)

**Focus:** Core team is establishing:
- Technical architecture
- Cryptographic implementation
- Testing framework
- Development workflows

**Status:** Internal development only

### Future: Open Development (Planned)

When we open for contributions:

1. **Find an Issue:**
   - Check GitHub Issues
   - Look for `good-first-issue` labels
   - Ask in discussion channels

2. **Discuss First:**
   - Comment on the issue
   - Propose your approach
   - Get feedback before coding

3. **Develop:**
   - Fork the repository
   - Create a feature branch
   - Write code and tests
   - Follow code standards

4. **Submit:**
   - Create pull request
   - Address review feedback
   - Get approval from reviewers
   - Merge when ready

### Communication Channels

**Primary:**
- GitHub Issues (technical discussion)
- GitHub Discussions (general topics)

**Future:**
- IRC/Matrix (to be determined)
- Developer mailing list (to be determined)

**Not Used:**
- Discord (too centralized)
- Telegram (not suitable for development)
- Slack (not public enough)

---

## Code Standards

### Bitcoin Core Style

Follow Bitcoin Core coding standards:

**C++ Guidelines:**
```cpp
// Use Bitcoin Core naming conventions
class CKey {          // Classes: CamelCase with C prefix
    bool fValid;      // Members: camelCase with type prefix
    void SetValid();  // Methods: CamelCase
};

// Use Bitcoin Core patterns
CAmount nAmount = 0;  // Amount with n prefix
int64_t nTime = 0;    // Time with n prefix
std::vector<unsigned char> vch;  // Vector with v prefix

// Comments
// Single line comments use //
/* Multi-line comments
   use this style */

// No trailing whitespace
// No tabs (use 4 spaces)
// Max 120 characters per line
```

**Documentation:**
```cpp
/**
 * Brief description of function
 *
 * Detailed description explaining what the function does,
 * its parameters, return value, and any side effects.
 *
 * @param[in] param1 Description of param1
 * @param[out] param2 Description of param2
 * @return Description of return value
 *
 * @note Any important notes
 * @warning Any warnings
 */
ReturnType FunctionName(Type1 param1, Type2& param2);
```

### Security-Critical Code

For cryptographic and consensus code, follow:
- `.claude/standards/security-critical-code.md`
- Constant-time operations
- Proper memory management
- Comprehensive testing

### Commit Messages

**Format (Bitcoin Core Style):**
```
component: Brief summary (50 chars or less)

More detailed explanation (if needed). Wrap at 72 characters.
Explain WHY the change was made, not just WHAT changed.

- Bullet points are okay
- Use present tense ("Add feature" not "Added feature")
- Reference issues (#123)
```

**Component Prefixes:**

Use these prefixes to categorize your commits (like Bitcoin Core):

- `consensus:` - Consensus-critical code (block validation, transaction rules)
- `crypto:` - Cryptographic primitives (Dilithium, SHA-3, key handling)
- `wallet:` - Wallet functionality
- `rpc:` - RPC interface changes
- `net:` - Network protocol and P2P code
- `mining:` - Mining and RandomX integration
- `test:` - Test-only changes
- `doc:` - Documentation updates
- `build:` - Build system and dependencies
- `refactor:` - Code refactoring (no behavior change)
- `fix:` - Bug fixes
- `perf:` - Performance improvements
- `ci:` - CI/CD configuration

**Examples:**

Good:
```
crypto: Implement Dilithium signature verification

Add constant-time Dilithium signature verification using
pqcrystals reference implementation. Includes comprehensive
unit tests and validation against NIST test vectors.

Closes #42
```

```
consensus: Fix off-by-one error in block height validation

The block height check was using <= instead of <, allowing
blocks one height too high to be accepted. This could have
allowed chain splits in rare edge cases.

Fixes #123
```

```
test: Add fuzz testing for transaction deserialization

Adds libFuzzer-based fuzzing for CTransaction deserialization
to catch potential crashes from malformed inputs.
```

Bad:
```
fixed stuff
```

```
wip
```

```
Update code (no component prefix, too vague)
```

---

## Testing Requirements

### All Code Must Be Tested

**No exceptions.** Every contribution must include tests.

### Test Types

#### 1. Unit Tests (Required)

```cpp
// src/test/dilithium_tests.cpp
BOOST_AUTO_TEST_CASE(dilithium_signature_verification) {
    CKey key;
    key.MakeNewKey();

    uint256 hash = Hash("test");
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));

    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.Verify(hash, sig));
}
```

#### 2. Functional Tests (When Applicable)

```python
# test/functional/feature_dilithium.py
def run_test(self):
    # Test that nodes accept Dilithium transactions
    tx = self.create_dilithium_transaction()
    self.nodes[0].sendrawtransaction(tx)
    self.sync_all()
```

#### 3. Fuzz Tests (For Parsers)

```cpp
// src/test/fuzz/dilithium.cpp
void test_one_input(const std::vector<uint8_t>& buffer) {
    // Should not crash on any input
    CPubKey pubkey;
    pubkey.Deserialize(buffer);
}
```

### Running Tests

```bash
# Unit tests
make check

# Functional tests
test/functional/test_runner.py

# Specific test
./src/test/test_bitcoin --run_test=dilithium_tests
```

### Coverage Requirements

**All PRs must meet coverage standards:**

#### Coverage Targets by Component

**P0 - Consensus Critical (REQUIRED: 80%+):**
- `src/consensus/` - Validation, PoW, subsidy rules
- `src/primitives/` - Block, transaction structures
- `src/crypto/dilithium3.cpp` - Signature operations

**P1 - High Priority (REQUIRED: 70%+):**
- `src/net/` - Network protocol, P2P
- `src/wallet/` - Wallet operations
- `src/rpc/` - RPC interface
- `src/node/mempool.cpp` - Mempool management

**P2 - Medium Priority (TARGET: 60%+):**
- `src/util/` - Utility functions
- `src/base58.cpp` - Address encoding
- `src/support/` - Support libraries

#### PR Coverage Rules

**For New Code:**
- Must achieve component's target coverage
- P0 code requires 80%+ coverage (no exceptions)
- P1 code requires 70%+ coverage
- Exceptions require justification in PR description

**For Modified Code:**
- Must not decrease overall coverage
- Codecov will comment on PR with coverage delta
- Coverage decrease of >5% will block PR
- Must cover modified lines + edge cases

**For Refactoring:**
- Coverage must remain same or improve
- Use refactoring to improve testability
- Add tests if previously untested

#### Checking Coverage

**Before Submitting PR:**
```bash
# Generate coverage report
make coverage-clean
make coverage

# View report
open coverage_html/index.html

# Check your changed files
# Ensure they meet component targets
```

**In CI:**
- Coverage report generated automatically
- Codecov comments on PR with coverage change
- Badge shows current coverage
- Failed coverage check blocks merge

#### Coverage Best Practices

**DO:**
- ✅ Test both success and error paths
- ✅ Test boundary conditions (0, 1, max, max+1)
- ✅ Test error handling and exceptions
- ✅ Focus on critical paths first
- ✅ Write tests while coding (not after)

**DON'T:**
- ❌ Write tests just to hit 100%
- ❌ Test trivial getters/setters excessively
- ❌ Skip testing because "it's obvious"
- ❌ Submit PR without running coverage
- ❌ Ask for coverage exceptions without justification

#### Coverage Documentation

See [docs/COVERAGE.md](docs/COVERAGE.md) for:
- Detailed coverage guide
- Component-specific requirements
- How to improve coverage
- Troubleshooting tips
- CI/CD integration

---

## Pull Request Process

### Before Submitting

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Code follows style guidelines
- [ ] Commit messages are clear
- [ ] Documentation updated (if needed)
- [ ] No merge conflicts with main branch

### PR Description Template

```markdown
## Summary
Brief description of what this PR does.

## Motivation
Why is this change necessary?

## Changes
- List of specific changes made
- Organized by category if large PR

## Testing
How was this tested?
- Unit tests added: [list]
- Functional tests added: [list]
- Manual testing performed: [description]

## Checklist
- [ ] Code compiles
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Follows code standards

## Related Issues
Closes #123
References #456
```

### Review Process

#### 1. Automated Checks
   - CI/CD runs all tests
   - Linters check code style
   - Coverage reports generated

#### 2. Code Review and ACK/NACK System

We follow Bitcoin Core's review terminology:

**Review Tags:**
- **Concept ACK** - You agree with the general goal and approach
- **Approach ACK** - You agree with the implementation approach
- **utACK (untested ACK)** - Code looks correct but you haven't tested it
- **Tested ACK** - Code looks correct AND you've tested it
- **ACK** - Full approval (code review + testing complete)
- **NACK** - You disagree with the change (must explain why)
- **Concept NACK** - You disagree with the goal/approach fundamentally

**How to Review:**
```
Concept ACK

I agree this is needed. The approach of using constant-time operations
is the right way to prevent timing side-channels.
```

```
Tested ACK abc1234

I've reviewed the code and tested locally on Windows 10 and Ubuntu 22.04.
All unit tests pass and the new functionality works as expected.
```

```
NACK

This changes consensus behavior without adequate justification. The current
implementation already handles this edge case correctly in block.cpp:234.
We should not introduce breaking changes without clear benefit.
```

**Important:**
- Anyone can ACK or NACK (you don't need to be a core contributor)
- Multiple reviewers strengthen confidence in changes
- Address all NACKs before merging
- Trivial NACKs (style, nits) may be overruled
- Consensus-critical NACKs must be resolved

#### 3. Testing
   - Reviewers test changes locally
   - Verify functionality
   - Check for edge cases

#### 4. Approval Requirements

**For Merge:**
- At least 2 Tested ACKs from different reviewers
- No unresolved NACKs
- All CI checks pass
- No merge conflicts
- Security-critical code needs specialist review

### Review Timeline

- Simple changes: 1-3 days
- Complex changes: 1-2 weeks
- Security-critical: 2-4 weeks

**Be patient.** Thorough review is more important than speed.

---

## Areas of Contribution

### Current Needs (Future)

When we open for contributions, these areas will need help:

#### 1. Core Development
**Skills:** C++, cryptography, Bitcoin Core knowledge
**Areas:**
- Dilithium integration
- Transaction handling
- Wallet implementation
- Network protocol

#### 2. Testing
**Skills:** C++, Python, QA experience
**Areas:**
- Unit test expansion
- Functional test development
- Fuzz testing
- Performance testing

#### 3. Documentation
**Skills:** Technical writing, cryptography knowledge
**Areas:**
- User guides
- API documentation
- Tutorial creation
- FAQ maintenance

#### 4. Security Research
**Skills:** Security analysis, cryptography
**Areas:**
- Code review
- Vulnerability research
- Side-channel analysis
- Threat modeling

#### 5. Tooling
**Skills:** Python, JavaScript, DevOps
**Areas:**
- Block explorer
- Wallet tools
- Build automation
- CI/CD improvements

### Not Needed

We do NOT need:
- ❌ Marketing materials
- ❌ Price speculation
- ❌ Exchange integration (too early)
- ❌ Mobile wallets (too early)
- ❌ Feature additions beyond quantum resistance

---

## Recognition

### Contribution Credits

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Acknowledged in academic papers (if applicable)

### Co-Authorship

Significant contributors may be offered:
- Co-authorship on academic papers
- Recognition in project documentation
- Role in project governance (future)

---

## Legal

### Licensing

By contributing, you agree that:
- Your contributions will be licensed under MIT License (planned)
- You have the right to submit the contribution
- You grant the project rights to use your contribution

### Copyright

- You retain copyright of your contributions
- You grant the project a perpetual license to use them
- No contributor agreement required (for now)

### Patents

- You grant a patent license for any patents in your contribution
- No defensive termination clauses
- Standard open source patent protection

---

## Questions?

### Before Contributing

If you want to contribute but aren't sure how:

1. Read all documentation
2. Set up development environment
3. Look at open issues
4. Ask questions in discussions

### Getting Help

- **Technical questions:** GitHub Discussions
- **Bug reports:** GitHub Issues
- **Security issues:** See SECURITY.md (future)

---

## Timeline

### Phase 0 (Now): Foundation
**Status:** Internal development only
**Expected:** Oct 2025 - Jan 2026

### Phase 1 (Future): Open Development
**Status:** Accept contributions
**Expected:** Feb 2026+
**Areas:** Testing, documentation, code review

### Phase 2 (Future): Community Growth
**Status:** Broader participation
**Expected:** Mid 2026+
**Areas:** Feature development, optimization, tools

---

## Final Notes

### This is a Long-Term Project

- Development will take years
- We won't rush for deadlines
- Security comes before features
- Quality over quantity

### We're Building Infrastructure

- This isn't a get-rich-quick scheme
- Focus on technical excellence
- Preparing for quantum era
- Long-term value creation

### Join Us

When we open for contributions, we'd love your help. Until then:
- Follow the repository
- Read the documentation
- Learn about post-quantum crypto
- Prepare to contribute

---

**Thank you for your interest in Dilithion!**

We're building something important. Join us when we're ready.

---

**Last Updated:** October 2025
**Next Review:** After Phase 0 completion (Jan 2026)
