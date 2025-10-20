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

**Format:**
```
Brief summary (50 chars or less)

More detailed explanation (if needed). Wrap at 72 characters.
Explain WHY the change was made, not just WHAT changed.

- Bullet points are okay
- Use present tense ("Add feature" not "Added feature")
- Reference issues (#123)
```

**Examples:**

Good:
```
Implement Dilithium signature verification

Add constant-time Dilithium signature verification using
pqcrystals reference implementation. Includes comprehensive
unit tests and validation against NIST test vectors.

Closes #42
```

Bad:
```
fixed stuff
```

```
wip
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

- New code: 100% line coverage
- Modified code: Maintain or improve coverage
- Critical code: 100% branch coverage

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

1. **Automated Checks:**
   - CI/CD runs all tests
   - Linters check code style
   - Coverage reports generated

2. **Code Review:**
   - At least 2 reviewers required
   - Security-critical code needs specialist review
   - Address all review comments

3. **Testing:**
   - Reviewers test changes locally
   - Verify functionality
   - Check for edge cases

4. **Approval:**
   - All reviewers approve
   - All CI checks pass
   - No merge conflicts
   - Ready to merge

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
