#!/bin/bash
# Test script for SSL/TLS functionality
# Copyright (c) 2025 The Dilithion Core developers

set -e

echo "=== Testing SSL/TLS Support ==="
echo ""

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo "ERROR: OpenSSL not found. Please install OpenSSL."
    exit 1
fi

# Create test directory
TEST_DIR=$(mktemp -d)
cd "$TEST_DIR"

echo "1. Generating test certificate and key..."
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem \
    -days 365 -nodes -subj "/CN=localhost" 2>/dev/null

if [ ! -f test_cert.pem ] || [ ! -f test_key.pem ]; then
    echo "ERROR: Failed to generate test certificate"
    exit 1
fi

echo "   ✓ Certificate generated: test_cert.pem"
echo "   ✓ Private key generated: test_key.pem"
echo ""

echo "2. Verifying certificate and key..."
openssl x509 -in test_cert.pem -text -noout > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✓ Certificate is valid"
else
    echo "   ✗ Certificate is invalid"
    exit 1
fi

openssl rsa -in test_key.pem -check > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✓ Private key is valid"
else
    echo "   ✗ Private key is invalid"
    exit 1
fi

# Verify key matches certificate
CERT_HASH=$(openssl x509 -noout -modulus -in test_cert.pem | openssl md5)
KEY_HASH=$(openssl rsa -noout -modulus -in test_key.pem | openssl md5)

if [ "$CERT_HASH" == "$KEY_HASH" ]; then
    echo "   ✓ Certificate and key match"
else
    echo "   ✗ Certificate and key do not match"
    exit 1
fi
echo ""

echo "3. Testing certificate loading (requires node build)..."
echo "   Note: This requires the node to be built with SSL support"
echo "   To test:"
echo "   1. Copy test_cert.pem and test_key.pem to your data directory"
echo "   2. Add to dilithion.conf:"
echo "      rpcsslcertificatechainfile=$TEST_DIR/test_cert.pem"
echo "      rpcsslprivatekeyfile=$TEST_DIR/test_key.pem"
echo "   3. Start node and verify SSL initialization message"
echo ""

echo "=== SSL/TLS Test Complete ==="
echo ""
echo "Test files created in: $TEST_DIR"
echo "  - test_cert.pem"
echo "  - test_key.pem"
echo ""
echo "To clean up: rm -rf $TEST_DIR"

