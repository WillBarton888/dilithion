#!/usr/bin/env python3
import re

with open('src/node/dilithion-node.cpp', 'r') as f:
    content = f.read()

old = '''                        // We don't know exact height, but headers manager can help
                        int currentHeight = g_chainstate.GetHeight();
                        int estimatedParentHeight = currentHeight;  // Conservative estimate

                        // Queue parent block for download with high priority
                        g_node_context.block_fetcher->QueueBlockForDownload(
                            block.hashPrevBlock,
                            estimatedParentHeight,
                            peer_id,  // Prefer same peer that sent orphan
                            true      // High priority - orphan parent needed urgently
                        );
                        std::cout << "[Orphan] Queued parent block " << block.hashPrevBlock.GetHex().substr(0, 16)
                                  << "... for download (high priority)" << std::endl;'''

new = '''                        // FIX: Get parent height from headers and check if already connected
                        int parentHeight = g_node_context.headers_manager->GetHeightForHash(block.hashPrevBlock);
                        int chainHeight = g_chainstate.GetHeight();
                        if (parentHeight <= 0) parentHeight = chainHeight;

                        // Only queue if parent is ahead of chain
                        if (parentHeight > chainHeight) {
                            g_node_context.block_fetcher->QueueBlockForDownload(
                                block.hashPrevBlock,
                                parentHeight,
                                peer_id,
                                true  // High priority
                            );
                            std::cout << "[Orphan] Queued parent at height " << parentHeight << std::endl;
                        } else {
                            std::cout << "[Orphan] Parent at height " << parentHeight << " already in chain" << std::endl;
                        }'''

if old in content:
    content = content.replace(old, new)
    with open('src/node/dilithion-node.cpp', 'w') as f:
        f.write(content)
    print('SUCCESS: Edit applied')
else:
    print('ERROR: Old text not found')
