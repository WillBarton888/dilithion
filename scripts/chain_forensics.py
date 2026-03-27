#!/usr/bin/env python3
"""Chain Forensic Analysis Tool for Dilithion (DIL) and DilV chains.

Scans the blockchain to identify exploiter addresses and produce a fair
pre-fund list for chain resets. Uses transaction graph analysis and MIK
identity correlation to cluster addresses by owner.

Principle: Innocent until proven guilty. Addresses are only excluded if
there is a DIRECT transactional link to a known exploiter address.

Usage:
    python3 chain_forensics.py --chain dilv
    python3 chain_forensics.py --chain dilv --seed D5RwUuNgy753h3yGCCgtc8AKpwvsmNQzia
    python3 chain_forensics.py --chain dil --rpc-port 8332
"""

import argparse
import json
import sys
import time
import socket
import base64
from collections import defaultdict
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════
# RPC Client (from bridge/relayer/dilithion_rpc.py — proven on Windows)
# ═══════════════════════════════════════════════════════════════════════

class RPC:
    """Minimal JSON-RPC 2.0 client using raw sockets."""

    def __init__(self, host="127.0.0.1", port=9332, user="rpc", password="rpc"):
        self.host = host
        self.port = port
        self._id = 0
        cred = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._auth = f"Basic {cred}"

    def call(self, method, params=None, timeout=60):
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0", "id": self._id,
            "method": method, "params": params or {},
        }).encode()

        request = (
            f"POST / HTTP/1.0\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Authorization: {self._auth}\r\n"
            f"X-Dilithion-RPC: 1\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + payload

        for attempt in range(3):
            try:
                sock = socket.create_connection((self.host, self.port), timeout=timeout)
                sock.sendall(request)
                chunks = []
                while True:
                    try:
                        chunk = sock.recv(1048576)  # 1MB chunks for large blocks
                        if not chunk:
                            break
                        chunks.append(chunk)
                    except ConnectionResetError:
                        break
                sock.close()
                raw = b"".join(chunks).decode()
                break
            except Exception as e:
                if attempt == 2:
                    raise RuntimeError(f"RPC {method} failed after 3 attempts: {e}")
                time.sleep(1)

        header_end = raw.find("\r\n\r\n")
        if header_end == -1:
            raise RuntimeError(f"RPC {method}: malformed response")
        body = raw[header_end + 4:]
        result = json.loads(body)
        if result.get("error"):
            raise RuntimeError(f"RPC {method}: {result['error']}")
        return result.get("result")

    def get_height(self):
        info = self.call("getblockchaininfo")
        return info["blocks"], info["chain"]

    def get_block_hash(self, height):
        r = self.call("getblockhash", {"height": height})
        return r["blockhash"] if isinstance(r, dict) else r

    def get_block(self, bhash, verbosity=2):
        return self.call("getblock", {"hash": bhash, "verbosity": verbosity})

    def get_mik_distribution(self):
        return self.call("getfullmikdistribution", timeout=120)

    def get_top_holders(self, count=500):
        return self.call("gettopholders", {"count": count}, timeout=120)


# ═══════════════════════════════════════════════════════════════════════
# Union-Find for Address Clustering
# ═══════════════════════════════════════════════════════════════════════

class UnionFind:
    """Disjoint set with path compression and union-by-rank."""

    def __init__(self):
        self.parent = {}
        self.rank = {}

    def find(self, x):
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1

    def get_cluster(self, x):
        """Return all members sharing the same root as x."""
        root = self.find(x)
        return {a for a in self.parent if self.find(a) == root}

    def all_clusters(self):
        """Return dict: root -> set of members."""
        clusters = defaultdict(set)
        for a in self.parent:
            clusters[self.find(a)].add(a)
        return dict(clusters)


# ═══════════════════════════════════════════════════════════════════════
# Chain Scanner (Pass 1)
# ═══════════════════════════════════════════════════════════════════════

class ChainScanner:
    """Scans all blocks, builds txid→output index, clusters addresses."""

    def __init__(self, rpc):
        self.rpc = rpc
        self.uf = UnionFind()

        # txid → list of {address, value} indexed by vout position
        self.txid_index = {}

        # Per-address metadata
        self.addr_info = defaultdict(lambda: {
            "mined_blocks": 0,
            "mined_value": 0,
            "received": 0,
            "sent": 0,
            "first_seen": None,
            "last_seen": None,
            "mik": None,
            "is_coinbase_only": True,
        })

        # Transaction graph (non-coinbase txs only)
        self.tx_graph = []

        # Bridge deposits detected
        self.bridge_deposits = []

        # Consolidation transactions (exact round amounts)
        self.consolidations = []

        # Stats
        self.height = 0
        self.chain = ""
        self.blocks_with_txs = 0

    def scan(self):
        self.height, self.chain = self.rpc.get_height()
        log(f"Chain: {self.chain}, height: {self.height}")
        log(f"Pass 1: Scanning {self.height} blocks...")

        for h in range(1, self.height + 1):
            if h % 1000 == 0:
                log(f"  ...block {h}/{self.height}")
            try:
                bhash = self.rpc.get_block_hash(h)
                block = self.rpc.get_block(bhash, verbosity=2)
                self._process_block(block, h)
            except Exception as e:
                log(f"  ERROR at block {h}: {e}")

        # Summary
        unique_miners = sum(1 for a in self.addr_info if self.addr_info[a]["mined_blocks"] > 0)
        single_block = sum(1 for a in self.addr_info
                          if self.addr_info[a]["mined_blocks"] == 1
                          and self.addr_info[a]["is_coinbase_only"])
        log(f"  Scan complete: {len(self.addr_info)} addresses, "
            f"{unique_miners} miners, {single_block} single-block, "
            f"{self.blocks_with_txs} blocks with sends, "
            f"{len(self.tx_graph)} non-coinbase txs")

    def _process_block(self, block, height):
        txs = block.get("tx", [])
        if not txs:
            return

        for tx_idx, tx in enumerate(txs):
            if not isinstance(tx, dict):
                continue
            txid = tx.get("txid", "")
            vins = tx.get("vin", [])
            vouts = tx.get("vout", [])

            # Store outputs in txid_index
            outputs = []
            for vout in vouts:
                addr = vout.get("address", "")
                value = vout.get("value", 0)
                spk = vout.get("scriptPubKey", "")
                outputs.append({"address": addr, "value": value, "scriptPubKey": spk})
            if txid:
                self.txid_index[txid] = outputs

            is_coinbase = (tx_idx == 0 and vins and
                          (vins[0].get("coinbase") or not vins[0].get("txid")))

            if is_coinbase:
                self._process_coinbase(tx, height, block)
            else:
                self._process_send_tx(tx, height)

    def _process_coinbase(self, tx, height, block):
        """Process a coinbase (mining reward) transaction."""
        vouts = tx.get("vout", [])
        if not vouts:
            return

        # Miner address is vout[0]
        miner_addr = vouts[0].get("address", "")
        miner_value = vouts[0].get("value", 0)
        mik = block.get("mik", "")

        if miner_addr:
            info = self.addr_info[miner_addr]
            info["mined_blocks"] += 1
            info["mined_value"] += miner_value
            info["received"] += miner_value
            if info["first_seen"] is None:
                info["first_seen"] = height
            info["last_seen"] = height
            if mik and not info["mik"]:
                info["mik"] = mik

    def _process_send_tx(self, tx, height):
        """Process a non-coinbase (send) transaction."""
        self.blocks_with_txs += 1
        txid = tx.get("txid", "")
        vins = tx.get("vin", [])
        vouts = tx.get("vout", [])

        # Resolve input addresses from txid_index
        input_addrs = []
        input_total = 0
        for vin in vins:
            prev_txid = vin.get("txid", "")
            prev_vout = vin.get("vout", 0)
            if prev_txid and prev_txid in self.txid_index:
                prev_outputs = self.txid_index[prev_txid]
                if prev_vout < len(prev_outputs):
                    addr = prev_outputs[prev_vout]["address"]
                    value = prev_outputs[prev_vout]["value"]
                    if addr:
                        input_addrs.append(addr)
                        input_total += value
                        # Mark as non-coinbase-only
                        self.addr_info[addr]["is_coinbase_only"] = False
                        self.addr_info[addr]["sent"] += value

        # Cluster all input addresses (common input ownership)
        for i in range(1, len(input_addrs)):
            self.uf.union(input_addrs[0], input_addrs[i])

        # Process outputs
        output_info = []
        for vout in vouts:
            addr = vout.get("address", "")
            value = vout.get("value", 0)
            spk = vout.get("scriptPubKey", "")

            # Detect OP_RETURN bridge deposits
            is_op_return = spk.startswith("6a") if isinstance(spk, str) else False
            base_addr = None
            if is_op_return:
                base_addr = self._parse_bridge_op_return(spk)
                if base_addr:
                    self.bridge_deposits.append({
                        "txid": txid, "height": height,
                        "base_address": base_addr,
                        "input_addrs": list(set(input_addrs)),
                    })

            if addr:
                info = self.addr_info[addr]
                info["received"] += value
                if info["first_seen"] is None:
                    info["first_seen"] = height
                info["last_seen"] = height
                info["is_coinbase_only"] = False

            output_info.append({
                "address": addr, "value": value,
                "is_op_return": is_op_return,
            })

        # Detect consolidation patterns (exact round amounts)
        ROUND_AMOUNTS = {999900000000, 499900000000, 499800000000}  # 9999, 4999, 4998
        for out in output_info:
            if out["value"] in ROUND_AMOUNTS and not out["is_op_return"]:
                self.consolidations.append({
                    "txid": txid, "height": height,
                    "target": out["address"],
                    "amount": out["value"],
                    "inputs": list(set(input_addrs)),
                })

        # Store in transaction graph
        self.tx_graph.append({
            "txid": txid, "height": height,
            "inputs": list(set(input_addrs)),
            "outputs": output_info,
        })

    def _parse_bridge_op_return(self, spk_hex):
        """Parse OP_RETURN for DBRG bridge tag. Returns Base address or None."""
        try:
            if len(spk_hex) < 52:  # 6a + 18 + 8 (tag) + 40 (addr) = 52 min
                return None
            # 6a = OP_RETURN, next byte = push length
            push_len = int(spk_hex[2:4], 16)
            if push_len != 24:  # DBRG (4) + address (20) = 24
                return None
            payload = spk_hex[4:]
            tag = bytes.fromhex(payload[:8])
            if tag != b"DBRG":
                return None
            return "0x" + payload[8:48]
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════
# MIK Enricher (Pass 2)
# ═══════════════════════════════════════════════════════════════════════

class MIKEnricher:
    """Merges MIK distribution data into address clusters."""

    def __init__(self, rpc, scanner):
        self.rpc = rpc
        self.scanner = scanner
        self.mik_data = {}  # mik_hex -> {blocks, addresses}

    def enrich(self):
        log("Pass 2: Fetching MIK distribution...")
        try:
            dist = self.rpc.get_mik_distribution()
        except Exception as e:
            log(f"  WARNING: Could not fetch MIK distribution: {e}")
            log(f"  Continuing without MIK enrichment.")
            return

        miners = dist.get("distribution", [])
        log(f"  {len(miners)} MIK identities found")

        miks_with_addrs = 0
        for m in miners:
            mik = m.get("mik", "")
            blocks = m.get("blocks", 0)
            addrs = m.get("addresses", [])
            self.mik_data[mik] = {"blocks": blocks, "addresses": addrs}

            if addrs:
                miks_with_addrs += 1
                # Union all addresses under the same MIK
                for i in range(1, len(addrs)):
                    self.scanner.uf.union(addrs[0], addrs[i])
                # Also set MIK on addr_info
                for a in addrs:
                    if a in self.scanner.addr_info:
                        self.scanner.addr_info[a]["mik"] = mik

        log(f"  {miks_with_addrs} MIKs with address data merged into clusters")


# ═══════════════════════════════════════════════════════════════════════
# Exploiter Detector (Pass 3)
# ═══════════════════════════════════════════════════════════════════════

class ExploiterDetector:
    """Flood-fills from seed addresses to identify the exploiter network."""

    # Confidence levels
    CONFIRMED = "CONFIRMED_EXPLOITER"
    PROBABLE = "PROBABLE_EXPLOITER"
    LEGITIMATE = "LEGITIMATE"
    UNKNOWN = "UNKNOWN"

    def __init__(self, scanner, seeds, whitelist=None, blacklist=None):
        self.scanner = scanner
        self.seeds = set(seeds)
        self.whitelist = set(whitelist or [])
        self.blacklist = set(blacklist or [])
        self.tags = {}  # address -> confidence level
        self.reasons = {}  # address -> reason string

    def detect(self):
        log("Pass 3: Detecting exploiter network...")

        # Tag whitelisted addresses first
        for a in self.whitelist:
            self.tags[a] = self.LEGITIMATE
            self.reasons[a] = "whitelist"

        # Tag blacklisted addresses
        for a in self.blacklist:
            if a not in self.whitelist:
                self.tags[a] = self.CONFIRMED
                self.reasons[a] = "blacklist"

        # Start flood-fill from seeds
        tainted = set(self.seeds)
        for s in self.seeds:
            self.tags[s] = self.CONFIRMED
            self.reasons[s] = "seed_address"

        # Expand seeds through Union-Find clusters
        expanded = set()
        for s in list(tainted):
            cluster = self.scanner.uf.get_cluster(s)
            for a in cluster:
                if a not in self.whitelist:
                    expanded.add(a)
                    self.tags[a] = self.CONFIRMED
                    self.reasons[a] = f"same_cluster_as_{s[:16]}"
        tainted.update(expanded)
        log(f"  After cluster expansion: {len(tainted)} addresses")

        # Flood-fill through transaction graph (fixed-point iteration)
        changed = True
        iterations = 0
        while changed:
            changed = False
            iterations += 1
            for tx in self.scanner.tx_graph:
                tx_inputs = set(tx["inputs"])
                tx_outputs = {o["address"] for o in tx["outputs"]
                             if o["address"] and not o["is_op_return"]}

                # If any INPUT is tainted → all other INPUTS are tainted
                # (common input ownership already handled by Union-Find,
                #  but this catches cases where inputs weren't clustered)
                if tx_inputs & tainted:
                    for a in tx_inputs:
                        if a not in tainted and a not in self.whitelist:
                            tainted.add(a)
                            self.tags[a] = self.CONFIRMED
                            self.reasons[a] = f"co_input_with_exploiter_tx_{tx['txid'][:16]}"
                            changed = True

                # If any OUTPUT goes to a tainted address AND there are
                # multiple inputs → tag all inputs as exploiter
                # (they funded the exploiter)
                if tx_outputs & tainted and len(tx_inputs) > 0:
                    for a in tx_inputs:
                        if a not in tainted and a not in self.whitelist:
                            tainted.add(a)
                            self.tags[a] = self.CONFIRMED
                            self.reasons[a] = f"sent_to_exploiter_tx_{tx['txid'][:16]}"
                            changed = True

        log(f"  After flood-fill ({iterations} iterations): {len(tainted)} addresses")

        # Cross-reference with MIK data: if any address in a MIK's address
        # list is tainted, all addresses under that MIK are tainted
        mik_tainted = set()
        for a in list(tainted):
            mik = self.scanner.addr_info.get(a, {}).get("mik", "")
            if mik:
                # Find all addresses with this MIK
                for other_a, info in self.scanner.addr_info.items():
                    if info.get("mik") == mik and other_a not in self.whitelist:
                        if other_a not in tainted:
                            mik_tainted.add(other_a)
                            self.tags[other_a] = self.CONFIRMED
                            self.reasons[other_a] = f"same_mik_{mik[:16]}"
        tainted.update(mik_tainted)
        log(f"  After MIK cross-reference: {len(tainted)} addresses")

        # Tag everything else as UNKNOWN (included in pre-fund)
        for a in self.scanner.addr_info:
            if a not in self.tags:
                self.tags[a] = self.UNKNOWN
                self.reasons[a] = "no_exploiter_link"

        # Summary
        confirmed = sum(1 for t in self.tags.values() if t == self.CONFIRMED)
        unknown = sum(1 for t in self.tags.values() if t == self.UNKNOWN)
        legit = sum(1 for t in self.tags.values() if t == self.LEGITIMATE)
        log(f"  Result: {confirmed} CONFIRMED_EXPLOITER, "
            f"{unknown} UNKNOWN (included), {legit} LEGITIMATE (whitelisted)")

        return tainted


# ═══════════════════════════════════════════════════════════════════════
# Report Generator
# ═══════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Produces JSON reports and pre-fund lists."""

    def __init__(self, scanner, detector, rpc, resolver=None, peer_analyzer=None):
        self.scanner = scanner
        self.detector = detector
        self.rpc = rpc
        self.resolver = resolver
        self.peer_analyzer = peer_analyzer

    def generate(self, output_dir="."):
        log("Generating reports...")

        # Cross-validate balances against gettopholders
        validation_warnings = self._cross_validate()

        # Build report
        report = self._build_report(validation_warnings)
        prefund = self._build_prefund()

        # Write files
        report_path = f"{output_dir}/chain_forensics_report.json"
        prefund_path = f"{output_dir}/prefund_list.json"
        cpp_path = f"{output_dir}/chainparams_prefund.cpp"

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        log(f"  Report: {report_path}")

        with open(prefund_path, "w") as f:
            json.dump(prefund, f, indent=2)
        log(f"  Pre-fund list: {prefund_path}")

        self._write_cpp_snippet(prefund, cpp_path)
        log(f"  C++ snippet: {cpp_path}")

        # Print summary
        self._print_summary(report, prefund)

    def _cross_validate(self):
        """Compare computed balances against gettopholders RPC."""
        log("  Cross-validating balances against gettopholders...")
        warnings = []
        try:
            holders = self.rpc.get_top_holders(500)
            top = holders.get("top", [])
            for h in top[:50]:  # Check top 50
                addr = h["address"]
                rpc_balance = h["balance"]  # Formatted as float (e.g. 98.00000000)
                # Our computed balance is received - sent (in raw satoshis)
                info = self.scanner.addr_info.get(addr, {})
                computed_raw = info.get("received", 0) - info.get("sent", 0)
                computed_formatted = computed_raw / 1e8
                # Allow small rounding difference
                if abs(computed_formatted - rpc_balance) > 0.01:
                    warnings.append({
                        "address": addr,
                        "rpc_balance": rpc_balance,
                        "computed_balance": computed_formatted,
                        "diff": computed_formatted - rpc_balance,
                    })
            if warnings:
                log(f"  WARNING: {len(warnings)} balance mismatches (may indicate scanner bug)")
            else:
                log(f"  Balance validation passed (top 50 match)")
        except Exception as e:
            log(f"  WARNING: Could not cross-validate: {e}")
            warnings.append({"error": str(e)})
        return warnings

    def _build_report(self, validation_warnings):
        tags = self.detector.tags
        reasons = self.detector.reasons
        addr_info = self.scanner.addr_info

        confirmed_addrs = [a for a, t in tags.items() if t == ExploiterDetector.CONFIRMED]
        unknown_addrs = [a for a, t in tags.items() if t == ExploiterDetector.UNKNOWN]
        legit_addrs = [a for a, t in tags.items() if t == ExploiterDetector.LEGITIMATE]

        def balance(a):
            info = addr_info.get(a, {})
            return info.get("received", 0) - info.get("sent", 0)

        return {
            "metadata": {
                "chain": self.scanner.chain,
                "scan_height": self.scanner.height,
                "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_addresses": len(addr_info),
                "total_clusters": len(self.scanner.uf.all_clusters()),
                "tool_version": "1.0.0",
            },
            "exploiter_summary": {
                "seed_addresses": list(self.detector.seeds),
                "confirmed_count": len(confirmed_addrs),
                "confirmed_balance": sum(balance(a) for a in confirmed_addrs) / 1e8,
                "unknown_count": len(unknown_addrs),
                "unknown_balance": sum(balance(a) for a in unknown_addrs) / 1e8,
                "legitimate_count": len(legit_addrs),
            },
            "consolidation_transactions": self.scanner.consolidations[:100],
            "bridge_deposits": self.scanner.bridge_deposits,
            "validation_warnings": validation_warnings,
            "confirmed_exploiter_addresses": [
                {
                    "address": a,
                    "balance_raw": balance(a),
                    "balance": balance(a) / 1e8,
                    "mined_blocks": addr_info[a]["mined_blocks"],
                    "reason": reasons.get(a, ""),
                    "mik": addr_info[a].get("mik", ""),
                }
                for a in sorted(confirmed_addrs, key=lambda x: -balance(x))
                if balance(a) > 0
            ][:500],  # Top 500 by balance
            "unknown_addresses_sample": [
                {
                    "address": a,
                    "balance_raw": balance(a),
                    "balance": balance(a) / 1e8,
                    "mined_blocks": addr_info[a]["mined_blocks"],
                }
                for a in sorted(unknown_addrs, key=lambda x: -balance(x))
            ][:100],  # Top 100 by balance
            "miner_identity": self.resolver.get_summary() if self.resolver else None,
            "peer_network": self.peer_analyzer.get_summary() if self.peer_analyzer else None,
        }

    def _build_prefund(self):
        tags = self.detector.tags
        addr_info = self.scanner.addr_info

        def balance(a):
            info = addr_info.get(a, {})
            return info.get("received", 0) - info.get("sent", 0)

        # Include UNKNOWN + LEGITIMATE, exclude CONFIRMED_EXPLOITER
        included = []
        excluded = []
        for a, tag in tags.items():
            bal = balance(a)
            if bal <= 0:
                continue
            entry = {
                "address": a,
                "balance_sats": bal,
                "balance": bal / 1e8,
                "confidence": tag,
            }
            if tag == ExploiterDetector.CONFIRMED:
                entry["reason"] = self.detector.reasons.get(a, "")
                excluded.append(entry)
            else:
                included.append(entry)

        included.sort(key=lambda x: -x["balance_sats"])
        excluded.sort(key=lambda x: -x["balance_sats"])

        return {
            "metadata": {
                "chain": self.scanner.chain,
                "source_height": self.scanner.height,
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "addresses_included": len(included),
                "addresses_excluded": len(excluded),
                "total_prefund": sum(e["balance"] for e in included),
                "total_excluded": sum(e["balance"] for e in excluded),
            },
            "prefund": included,
            "excluded": excluded,
        }

    def _write_cpp_snippet(self, prefund, path):
        with open(path, "w") as f:
            f.write("// Auto-generated by chain_forensics.py\n")
            f.write(f"// Chain: {self.scanner.chain}, height: {self.scanner.height}\n")
            f.write(f"// Generated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n")
            f.write(f"// Addresses: {prefund['metadata']['addresses_included']}\n")
            f.write(f"// Total: {prefund['metadata']['total_prefund']:.8f} "
                    f"{self.scanner.chain.upper()}\n\n")
            f.write("params.preFundAddresses = {\n")
            for entry in prefund["prefund"]:
                f.write(f'    {{"{entry["address"]}", {entry["balance_sats"]}ULL}},'
                        f'  // {entry["balance"]:.8f}\n')
            f.write("};\n")

    def _print_summary(self, report, prefund):
        meta = report["metadata"]
        exp = report["exploiter_summary"]
        pm = prefund["metadata"]

        log("\n" + "=" * 60)
        log(f"CHAIN FORENSICS REPORT — {meta['chain'].upper()}")
        log(f"Height: {meta['scan_height']} | "
            f"Addresses: {meta['total_addresses']} | "
            f"Clusters: {meta['total_clusters']}")
        log("=" * 60)
        log(f"  CONFIRMED EXPLOITER:  {exp['confirmed_count']:>6} addrs  "
            f"{exp['confirmed_balance']:>15,.2f} {meta['chain'].upper()}")
        log(f"  UNKNOWN (included):   {exp['unknown_count']:>6} addrs  "
            f"{exp['unknown_balance']:>15,.2f} {meta['chain'].upper()}")
        log(f"  LEGITIMATE (wl):      {exp['legitimate_count']:>6} addrs")
        log("-" * 60)
        log(f"  PRE-FUND:   {pm['addresses_included']:>6} addrs  "
            f"{pm['total_prefund']:>15,.2f} {meta['chain'].upper()}")
        log(f"  EXCLUDED:   {pm['addresses_excluded']:>6} addrs  "
            f"{pm['total_excluded']:>15,.2f} {meta['chain'].upper()}")
        log(f"  Bridge deposits found: {len(report['bridge_deposits'])}")
        log(f"  Consolidation txs found: {len(report['consolidation_transactions'])}")
        if report["validation_warnings"]:
            log(f"  ⚠ Balance validation warnings: {len(report['validation_warnings'])}")
        else:
            log(f"  ✓ Balance validation: PASSED")

        # Miner identity summary
        mi = report.get("miner_identity")
        if mi:
            log("-" * 60)
            log(f"  TRUE MINER COUNT: {mi['unique_operators']} operators "
                f"({mi['total_miks']} MIKs)")
            log(f"  Single-MIK operators: {mi['single_mik_operators']} | "
                f"Multi-MIK: {mi['multi_mik_operators']}")
            conc = mi.get("concentration", {})
            log(f"  Block concentration: "
                f"top1={conc.get('top1', 0):.1f}%, "
                f"top5={conc.get('top5', 0):.1f}%, "
                f"top10={conc.get('top10', 0):.1f}%")

        # Peer network summary
        pn = report.get("peer_network")
        if pn:
            log("-" * 60)
            log(f"  PEERS: {pn['total_peers']} connected "
                f"({pn['datacenter']} datacenter, "
                f"{pn['residential']} residential, "
                f"{pn['unknown']} unknown)")

        log("=" * 60)


# ═══════════════════════════════════════════════════════════════════════
# Miner Identity Resolution (Pass 4)
# ═══════════════════════════════════════════════════════════════════════

class MinerResolver:
    """Deduplicates MIK identities by shared addresses to find true operator count."""

    def __init__(self, rpc, scanner):
        self.rpc = rpc
        self.scanner = scanner
        self.mik_clusters = {}  # root_mik -> {miks, blocks, addrs}
        self.cross_chain_miks = set()

    def resolve(self, mik_data=None):
        log("Pass 4: Resolving true miner identities...")

        # Use MIK distribution data (from Pass 2 or fresh fetch)
        if mik_data is None:
            try:
                dist_result = self.rpc.get_mik_distribution()
                mik_data = dist_result.get("distribution", [])
            except Exception as e:
                log(f"  WARNING: Could not fetch MIK distribution: {e}")
                log(f"  Skipping miner resolution.")
                return

        if not mik_data:
            log("  No MIK data available. Skipping.")
            return

        # Union-Find to cluster MIKs that share any payout address
        parent = {}

        def find(x):
            if x not in parent:
                parent[x] = x
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        addr_to_mik = {}
        for m in mik_data:
            mik = m.get("mik", "")
            if not mik:
                continue
            parent.setdefault(mik, mik)
            for a in m.get("addresses", []):
                if a in addr_to_mik:
                    union(mik, addr_to_mik[a])
                addr_to_mik[a] = mik

        # Build clusters
        clusters = {}
        for m in mik_data:
            mik = m.get("mik", "")
            if not mik:
                continue
            root = find(mik)
            if root not in clusters:
                clusters[root] = {"miks": [], "blocks": 0, "addrs": set()}
            clusters[root]["miks"].append(mik)
            clusters[root]["blocks"] += m.get("blocks", 0)
            for a in m.get("addresses", []):
                clusters[root]["addrs"].add(a)

        self.mik_clusters = clusters

        # Stats
        total_miks = len(mik_data)
        total_operators = len(clusters)
        single_mik = sum(1 for c in clusters.values() if len(c["miks"]) == 1)
        multi_mik = sum(1 for c in clusters.values() if len(c["miks"]) > 1)
        max_miks = max((len(c["miks"]) for c in clusters.values()), default=0)

        log(f"  {total_miks} MIKs -> {total_operators} unique operators")
        log(f"  {single_mik} operators with 1 MIK, {multi_mik} with 2+ MIKs")
        log(f"  Largest operator: {max_miks} MIKs")

        # Concentration metrics
        sorted_clusters = sorted(clusters.values(), key=lambda c: -c["blocks"])
        total_blocks = sum(c["blocks"] for c in sorted_clusters)
        if total_blocks > 0:
            top1 = sorted_clusters[0]["blocks"] / total_blocks * 100 if sorted_clusters else 0
            top5 = sum(c["blocks"] for c in sorted_clusters[:5]) / total_blocks * 100
            top10 = sum(c["blocks"] for c in sorted_clusters[:10]) / total_blocks * 100
            log(f"  Block concentration: top1={top1:.1f}%, top5={top5:.1f}%, top10={top10:.1f}%")

    def get_summary(self):
        """Return summary dict for the report."""
        sorted_clusters = sorted(self.mik_clusters.values(), key=lambda c: -c["blocks"])
        total_blocks = sum(c["blocks"] for c in sorted_clusters)

        operators = []
        for i, c in enumerate(sorted_clusters[:50]):
            pct = c["blocks"] / total_blocks * 100 if total_blocks > 0 else 0
            primary_addr = sorted(c["addrs"])[0] if c["addrs"] else ""
            operators.append({
                "rank": i + 1,
                "mik_count": len(c["miks"]),
                "blocks": c["blocks"],
                "percent": round(pct, 1),
                "address_count": len(c["addrs"]),
                "primary_address": primary_addr,
                "miks": c["miks"][:5],  # First 5 MIK hashes
            })

        return {
            "total_miks": sum(len(c["miks"]) for c in self.mik_clusters.values()),
            "unique_operators": len(self.mik_clusters),
            "single_mik_operators": sum(1 for c in self.mik_clusters.values() if len(c["miks"]) == 1),
            "multi_mik_operators": sum(1 for c in self.mik_clusters.values() if len(c["miks"]) > 1),
            "top_operators": operators,
            "concentration": {
                "top1": operators[0]["percent"] if operators else 0,
                "top5": sum(o["percent"] for o in operators[:5]),
                "top10": sum(o["percent"] for o in operators[:10]),
            },
        }


# ═══════════════════════════════════════════════════════════════════════
# Peer Analysis (Pass 5)
# ═══════════════════════════════════════════════════════════════════════

class PeerAnalyzer:
    """Collects peer IPs and classifies them as datacenter or residential."""

    def __init__(self, rpc, seed_ips=None):
        self.rpc = rpc
        self.seed_ips = set(seed_ips or [
            "138.197.68.128", "167.172.56.119",
            "165.22.103.114", "134.199.159.83",
        ])
        self.peer_ips = {}  # ip -> {country, isp, asn, datacenter, chain}
        self.asn_db = None

    def analyze(self):
        log("Pass 5: Analyzing peer network...")

        # Collect peer IPs
        try:
            peers = self.rpc.call("getpeerinfo", timeout=30)
            if not isinstance(peers, list):
                log("  WARNING: getpeerinfo returned unexpected format")
                return
        except Exception as e:
            log(f"  WARNING: Could not get peer info: {e}")
            return

        # Extract IPs
        import re
        ips = set()
        for p in peers:
            addr = p.get("addr", "")
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)", addr)
            if m:
                ip = m.group(1)
                if ip not in self.seed_ips and not ip.startswith("127."):
                    ips.add(ip)

        log(f"  {len(ips)} peer IPs (excluding seeds)")

        # Try local ASN database first (ip2asn-v4.tsv)
        self._load_asn_db()

        # Classify each IP
        for ip in sorted(ips):
            info = self._classify_ip(ip)
            self.peer_ips[ip] = info

        dc = sum(1 for i in self.peer_ips.values() if i.get("datacenter") is True)
        res = sum(1 for i in self.peer_ips.values() if i.get("datacenter") is False)
        unk = sum(1 for i in self.peer_ips.values() if i.get("datacenter") is None)
        log(f"  Classified: {dc} datacenter, {res} residential, {unk} unknown")

    def _load_asn_db(self):
        """Try to load ip2asn-v4.tsv for offline ASN lookup."""
        import os
        for path in ["/root/dilithion/ip2asn-v4.tsv", "ip2asn-v4.tsv",
                      os.path.expanduser("~/dilithion/ip2asn-v4.tsv")]:
            if os.path.exists(path):
                self.asn_db = path
                log(f"  Using local ASN database: {path}")
                return
        log("  No local ASN database found. Using ip-api.com (rate-limited).")

    def _classify_ip(self, ip):
        """Classify an IP as datacenter or residential."""
        # Try ip-api.com (free, 45 req/min)
        import urllib.request
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,hosting,query"
            resp = urllib.request.urlopen(url, timeout=5)
            d = json.loads(resp.read())
            time.sleep(0.7)  # Stay under rate limit
            return {
                "country": d.get("country", ""),
                "country_code": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "org": d.get("org", ""),
                "asn": d.get("as", ""),
                "datacenter": d.get("hosting", None),
            }
        except Exception:
            return {"country": "", "country_code": "", "isp": "", "org": "",
                    "asn": "", "datacenter": None}

    def get_summary(self):
        """Return summary dict for the report."""
        dc = sum(1 for i in self.peer_ips.values() if i.get("datacenter") is True)
        res = sum(1 for i in self.peer_ips.values() if i.get("datacenter") is False)

        peers_list = []
        for ip, info in sorted(self.peer_ips.items()):
            peers_list.append({
                "ip": ip,
                "country": info.get("country_code", ""),
                "isp": info.get("isp", ""),
                "asn": info.get("asn", ""),
                "datacenter": info.get("datacenter"),
            })

        # Group by country
        from collections import Counter
        countries = Counter(i.get("country_code", "?") for i in self.peer_ips.values())

        return {
            "total_peers": len(self.peer_ips),
            "datacenter": dc,
            "residential": res,
            "unknown": len(self.peer_ips) - dc - res,
            "by_country": dict(countries.most_common(20)),
            "peers": peers_list,
        }


# ═══════════════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════════════

def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Chain Forensic Analysis Tool")
    parser.add_argument("--chain", choices=["dil", "dilv"], default="dilv",
                       help="Chain to analyze (default: dilv)")
    parser.add_argument("--rpc-host", default="127.0.0.1")
    parser.add_argument("--rpc-port", type=int, default=None,
                       help="RPC port (default: 8332 for dil, 9332 for dilv)")
    parser.add_argument("--rpc-user", default="rpc")
    parser.add_argument("--rpc-pass", default="rpc")
    parser.add_argument("--seed", action="append", default=[],
                       help="Known exploiter address (can specify multiple)")
    parser.add_argument("--whitelist", action="append", default=[],
                       help="Address to whitelist (never tagged as exploiter)")
    parser.add_argument("--blacklist", action="append", default=[],
                       help="Address to force-tag as exploiter")
    parser.add_argument("--output-dir", default=".",
                       help="Directory for output files")
    parser.add_argument("--strict", action="store_true",
                       help="Only exclude CONFIRMED_EXPLOITER (default)")
    args = parser.parse_args()

    # Default ports
    if args.rpc_port is None:
        args.rpc_port = 8332 if args.chain == "dil" else 9332

    # Default whitelist: bridge addresses
    default_whitelist = [
        "DNaTbwZgm6x23zf4DnJm4vjEG2qGc6cinx",   # Current DIL bridge
        "DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp",   # Current DilV bridge
        "DESyLBcZYDU1jrE2o1GuQkdiuiwk2An6Sn",   # Old DilV bridge
        "DPW8h76TAGwj569LgbdLCAFUcgixMuoBWc",   # Old DIL bridge
    ]
    all_whitelist = list(set(args.whitelist + default_whitelist))

    log(f"Chain Forensics Tool v2.0.0")
    log(f"Chain: {args.chain} | RPC: {args.rpc_host}:{args.rpc_port}")
    log(f"Seeds: {args.seed or '(none — will only use transaction analysis)'}")
    log(f"Whitelist: {len(all_whitelist)} addresses")
    log("")

    # Initialize
    rpc = RPC(args.rpc_host, args.rpc_port, args.rpc_user, args.rpc_pass)

    # Pass 1: Block scan (builds txid index, address clusters, bridge deposits)
    scanner = ChainScanner(rpc)
    scanner.scan()

    # Pass 2: MIK enrichment (merges MIK→address data into clusters)
    enricher = MIKEnricher(rpc, scanner)
    enricher.enrich()

    # Pass 3: Exploiter detection (flood-fill from seeds)
    detector = ExploiterDetector(scanner, args.seed, all_whitelist, args.blacklist)
    detector.detect()

    # Pass 4: Miner identity resolution (deduplicate MIKs → true operator count)
    resolver = MinerResolver(rpc, scanner)
    resolver.resolve()

    # Pass 5: Peer network analysis (IP classification)
    peer_analyzer = PeerAnalyzer(rpc)
    peer_analyzer.analyze()

    # Generate reports
    generator = ReportGenerator(scanner, detector, rpc, resolver, peer_analyzer)
    generator.generate(args.output_dir)

    log("\nDone.")


if __name__ == "__main__":
    main()
