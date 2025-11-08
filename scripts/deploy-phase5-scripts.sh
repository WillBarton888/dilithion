#!/bin/bash
# Deploy Phase 5 scripts to all production nodes

set -e

NODES=("188.166.255.63" "134.122.4.164" "209.97.177.197")
LABELS=("Singapore" "NYC" "London")
SSH_KEY="${HOME}/.ssh/id_ed25519_windows"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no"

SCRIPTS=(
  "run-continuous-fuzz-campaign.sh"
  "monitor-fuzzer-resources.sh"
)

echo "=== Deploying Phase 5 Scripts ==="
echo ""

# Make scripts executable
chmod +x scripts/run-continuous-fuzz-campaign.sh scripts/monitor-fuzzer-resources.sh

for i in "${!NODES[@]}"; do
  NODE="${NODES[$i]}"
  LABEL="${LABELS[$i]}"

  echo "[$LABEL] Deploying to $NODE..."

  # Deploy scripts
  for SCRIPT in "${SCRIPTS[@]}"; do
    scp $SSH_OPTS "scripts/$SCRIPT" "root@$NODE:/root/" && echo "  ✓ $SCRIPT"
  done

  # Make executable on remote
  ssh $SSH_OPTS root@$NODE "chmod +x /root/run-continuous-fuzz-campaign.sh /root/monitor-fuzzer-resources.sh"

  echo "  ✓ Deployment complete"
  echo ""
done

echo "✓ All scripts deployed successfully"
echo ""
echo "To start fuzzing campaigns:"
echo "  Singapore (tier1): ssh root@188.166.255.63 'cd /root/dilithion-fuzzers && nohup ../run-continuous-fuzz-campaign.sh tier1 > campaign.log 2>&1 &'"
echo "  NYC (tier2): ssh root@134.122.4.164 'cd /root/dilithion-fuzzers && nohup ../run-continuous-fuzz-campaign.sh tier2 > campaign.log 2>&1 &'"
echo "  London (tier3): ssh root@209.97.177.197 'cd /root/dilithion-fuzzers && nohup ../run-continuous-fuzz-campaign.sh tier3 > campaign.log 2>&1 &'"
