#!/usr/bin/env bash
# Regenerate src/api/{wallet,miner}_html.h from website/{wallet,miner}.html.
# The embedded C++ headers are served from the node's built-in HTTP server.
# Run this whenever you edit the website HTML to keep them in sync.

set -euo pipefail

gen() {
    local src="$1" out="$2" fn="$3" guard="$4" marker="$5"

    if [[ ! -f "$src" ]]; then
        echo "error: $src missing" >&2; exit 1
    fi

    {
        cat <<HEADER
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// AUTO-GENERATED FILE - DO NOT EDIT DIRECTLY
// Generated from $src by scripts/gen-embedded-html.sh

#ifndef $guard
#define $guard

#include <string>

inline const std::string& $fn() {
    static const std::string html = R"$marker(
HEADER
        cat "$src"
        cat <<FOOTER
)$marker";
    return html;
}

#endif // $guard
FOOTER
    } > "$out"

    echo "wrote $out ($(wc -c < "$out") bytes)"
}

cd "$(dirname "$0")/.."

gen website/wallet.html src/api/wallet_html.h \
    GetWalletHTML DILITHION_API_WALLET_HTML_H WALLET_HTML

gen website/miner.html src/api/miner_html.h \
    GetMinerHTML DILITHION_API_MINER_HTML_H MINER_HTML
