# Pull Request

## Component

<!-- Use Bitcoin Core-style component prefix in PR title -->
<!-- Examples: -->
<!-- consensus: Fix block validation edge case -->
<!-- crypto: Optimize Dilithium signature verification -->
<!-- wallet: Add HD wallet support -->
<!-- net: Improve peer connection handling -->
<!-- test: Add fuzzing for transaction parser -->
<!-- doc: Update installation instructions -->

**Component:** `component-name` (consensus, crypto, wallet, rpc, net, mining, test, doc, build, refactor, fix, perf, ci)

## Summary

Brief description of what this PR does.

## Motivation

Why is this change necessary? What problem does it solve?

## Changes

### Core Changes
- List specific changes made
- Be clear and concise
- Group related changes

### Files Modified
- `path/to/file.cpp` - what changed
- `path/to/file.h` - what changed

## Testing

### Unit Tests
- [ ] Added unit tests for new functionality
- [ ] Updated existing unit tests
- [ ] All unit tests pass

### Functional Tests
- [ ] Added functional tests (if applicable)
- [ ] All functional tests pass

### Manual Testing
Describe manual testing performed:
```
Steps taken to test manually
```

### Test Coverage
- Current coverage: __%
- Coverage change: +/-__%

## Code Quality

- [ ] Follows Bitcoin Core code style
- [ ] No compiler warnings
- [ ] No linter warnings
- [ ] Documentation updated
- [ ] Code comments added where needed

## Security

- [ ] No security implications
- [ ] Security implications reviewed by security-auditor
- [ ] Cryptographic changes reviewed by crypto-specialist
- [ ] Consensus changes reviewed by consensus-validator

## Performance

- [ ] No performance impact
- [ ] Performance impact measured and acceptable
- [ ] Benchmarks added/updated

## Breaking Changes

- [ ] No breaking changes
- [ ] Breaking changes documented and justified

## Related Issues

Closes #(issue number)
References #(issue number)

## Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No merge conflicts
- [ ] Ready for review

## Review Notes

Any specific areas you'd like reviewers to focus on?

## For Reviewers

**How to Review:**

Use Bitcoin Core-style review tags:
- `Concept ACK` - Agree with the goal and approach
- `Approach ACK` - Agree with implementation approach
- `utACK <commit>` - Code looks correct (untested)
- `Tested ACK <commit>` - Code looks correct AND tested
- `ACK <commit>` - Full approval
- `NACK` - Disagree (must explain why)

**Approval Requirements:**
- At least 2 Tested ACKs required for merge
- All NACKs must be addressed
- All CI checks must pass

## Screenshots

If applicable, add screenshots to demonstrate changes.
