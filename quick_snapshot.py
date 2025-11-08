#!/usr/bin/env python3
import urllib.request
import json

nodes = {
    "Singapore": "188.166.255.63",
    "New York": "134.122.4.164",
    "London": "209.97.177.197"
}

print("=== Dilithion Testnet Quick Snapshot ===\n")

for name, ip in nodes.items():
    print(f"{name} ({ip}):")
    try:
        url = f"http://{ip}:8334/api/stats"
        response = urllib.request.urlopen(url, timeout=3)
        data = json.loads(response.read().decode())
        print(f"  Height: {data.get('blockHeight', 'N/A')}")
        print(f"  Peers: {data.get('peers', 'N/A')}")
        print(f"  Hashrate: {data.get('hashrate', 'N/A')} H/s")
        print(f"  Status: ✓ Online")
    except Exception as e:
        print(f"  Status: ✗ Error - {str(e)}")
    print("")
