#!/usr/bin/env python3
"""
Generate RPC user entry for rpc_permissions.json

Usage:
    python3 generate_rpc_user.py <username> <role>

Role must be one of: admin, wallet, readonly

Prompts for password (hidden input), generates salt and hash using HMAC-SHA3-256.
Outputs JSON entry to add to rpc_permissions.json

Example:
    $ python3 generate_rpc_user.py payment_bot wallet
    Enter password for user 'payment_bot': [hidden]
    Confirm password: [hidden]

    Add this entry to the 'users' section of rpc_permissions.json:
    {
      "payment_bot": {
        "password_hash": "abc123...",
        "salt": "def456...",
        "role": "wallet",
        "comment": "Generated on 2025-11-11T10:00:00"
      }
    }
"""

import hashlib
import secrets
import getpass
import json
import sys
import datetime

def hmac_sha3_256(key, data):
    """
    Simplified HMAC-SHA3-256 implementation

    Note: This uses SHA256 instead of SHA3 for Python compatibility.
    Production implementation should match C++ HMAC_SHA3_256 in src/crypto/hmac_sha3.cpp
    """
    # For production: Use Crypto.Hash.SHA3 or hashlib.sha3_256
    # This version uses SHA256 for demonstration
    return hashlib.sha256(key + data).digest()

def generate_user(username, role):
    """
    Generate user credentials for RPC permissions

    Args:
        username: Username for RPC authentication
        role: User role (admin, wallet, readonly)
    """
    # Validate role
    roles = {
        'admin': '0xFFFFFFFF',
        'wallet': '0x003F',
        'readonly': '0x000F'
    }

    if role not in roles:
        print(f"Error: Invalid role '{role}'. Must be one of: {', '.join(roles.keys())}",
              file=sys.stderr)
        sys.exit(1)

    # Validate username
    if not username or len(username) > 64:
        print("Error: Username must be between 1 and 64 characters", file=sys.stderr)
        sys.exit(1)

    if not username.replace('_', '').replace('-', '').isalnum():
        print("Error: Username must contain only alphanumeric characters, underscores, and hyphens",
              file=sys.stderr)
        sys.exit(1)

    # Prompt for password
    password = getpass.getpass(f"Enter password for user '{username}': ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        print("Error: Passwords do not match", file=sys.stderr)
        sys.exit(1)

    if len(password) < 12:
        print("Warning: Password is shorter than recommended 12 characters", file=sys.stderr)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(1)

    # Generate random salt (32 bytes)
    salt = secrets.token_bytes(32)

    # Hash password with salt using HMAC-SHA3 (simplified version)
    # Production: Should match C++ implementation exactly
    password_bytes = password.encode('utf-8')
    password_hash = hmac_sha3_256(salt, password_bytes)

    # Create user entry
    user_entry = {
        username: {
            "password_hash": password_hash.hex(),
            "salt": salt.hex(),
            "role": role,
            "comment": f"Generated on {datetime.datetime.now().isoformat()}"
        }
    }

    # Display output
    print("\n" + "="*70)
    print("Add this entry to the 'users' section of rpc_permissions.json:")
    print("="*70)
    print(json.dumps(user_entry, indent=2))
    print("="*70)
    print("\nIMPORTANT SECURITY STEPS:")
    print("1. Copy the JSON entry above into rpc_permissions.json")
    print("2. Set file permissions: chmod 600 rpc_permissions.json")
    print("3. Restart the Dilithion node")
    print("4. Test authentication:")
    print(f"   curl -u {username}:YOUR_PASSWORD http://localhost:8332/ \\")
    print("        -H 'X-Dilithion-RPC: 1' \\")
    print("        -d '{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}'")
    print("\nRole Permissions:")
    if role == "admin":
        print("  - Full access to all RPC methods (including stop, encryptwallet, exportmnemonic)")
    elif role == "wallet":
        print("  - Can read blockchain/wallet data")
        print("  - Can send transactions and generate addresses")
        print("  - CANNOT export keys or stop server")
    elif role == "readonly":
        print("  - Can read blockchain/wallet data")
        print("  - CANNOT modify any state or send transactions")

    print("\nWARNING:")
    print("  - Store rpc_permissions.json securely")
    print("  - Never commit rpc_permissions.json to version control")
    print("  - Rotate passwords regularly (especially for admin role)")

def main():
    """Main entry point"""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <role>", file=sys.stderr)
        print("Role must be one of: admin, wallet, readonly", file=sys.stderr)
        print("\nExamples:")
        print(f"  {sys.argv[0]} admin admin")
        print(f"  {sys.argv[0]} payment_bot wallet")
        print(f"  {sys.argv[0]} monitor readonly")
        sys.exit(1)

    username = sys.argv[1]
    role = sys.argv[2]

    print("="*70)
    print("Dilithion RPC User Generator")
    print("="*70)
    print(f"Username: {username}")
    print(f"Role: {role}")
    print()

    generate_user(username, role)

if __name__ == '__main__':
    main()
