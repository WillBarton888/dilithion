#!/bin/bash
# GitHub Release Creation Script for v1.0-testnet

# First, push the commit manually if not done yet:
# git push origin main

# Create the release tag and GitHub release
gh release create v1.0-testnet \
    --title "Dilithion v1.0-testnet - Public Testnet Launch" \
    --notes-file .github-release-notes.md \
    --prerelease \
    --target main

echo ""
echo "✅ Release created successfully!"
echo ""
echo "Next steps from TESTNET-LAUNCH-CHECKLIST.md:"
echo "- [ ] Pin TESTNET-LAUNCH.md in repository"
echo "- [ ] Create GitHub Discussion for testnet"
echo "- [ ] Enable GitHub Issues (if not already)"
echo "- [ ] Add repository topics: cryptocurrency, post-quantum, blockchain, quantum-resistant, dilithium, testnet"
echo "- [ ] Post announcements (Twitter, Reddit, Discord)"
