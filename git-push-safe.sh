#!/bin/bash
# Safe git push script for WSL
# Prevents hanging on credential prompts

set -e

# Ensure credential helper is configured
if [ "$(git config --global credential.helper)" == "" ]; then
    echo "Configuring Windows Git Credential Manager..."
    git config --global credential.helper '/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe'
fi

# Use GIT_TERMINAL_PROMPT=0 to prevent hanging on credential prompts
# If credentials aren't available, push will fail immediately instead of hanging
export GIT_TERMINAL_PROMPT=0

# Push with timeout as safety net
timeout 30 git push "$@"

exit_code=$?

if [ $exit_code -eq 124 ]; then
    echo "ERROR: Git push timed out after 30 seconds"
    echo "This usually means credential authentication is stuck"
    echo ""
    echo "To fix:"
    echo "1. Run 'git push' manually in Windows Git Bash to authenticate"
    echo "2. Or set up GitHub Personal Access Token"
    exit 1
elif [ $exit_code -ne 0 ]; then
    echo "ERROR: Git push failed with exit code $exit_code"
    exit $exit_code
fi

echo "✅ Push successful!"
