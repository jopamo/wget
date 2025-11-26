#!/bin/sh
# Test script for HTTP 302 redirects

set -eu

WGET_BIN="${WGET:-./build/src/wget}"
PORT=18081

# Check if wget binary exists
if [ ! -x "$WGET_BIN" ]; then
    echo "Error: wget binary not found at $WGET_BIN" >&2
    exit 1
fi

# Check if port is already in use using netcat
if command -v nc >/dev/null 2>&1; then
    if nc -z 127.0.0.1 ${PORT} >/dev/null 2>&1; then
        echo "Error: Port ${PORT} is already in use. Please free the port and try again." >&2
        exit 1
    fi
fi

# Start the test server in background
python3 "$(dirname "$0")/test-302-redirect.py" &
SERVER_PID=$!

# Give server time to start and verify it's running
sleep 2

# Verify server is actually running
if ! curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:${PORT}/hello.txt | grep -q "200"; then
    echo "Error: Test server failed to start on port ${PORT}" >&2
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Cleanup function
cleanup() {
    if [ "${SERVER_PID:-0}" -gt 0 ] 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f test_output.txt redirect_test.txt
}
trap cleanup EXIT INT TERM

echo "Testing HTTP 302 redirect handling..."

# Test 1: Single 302 redirect
echo "Test 1: Single 302 redirect"
"$WGET_BIN" \
    --no-config \
    --tries=1 \
    --timeout=5 \
    --output-document=test_output.txt \
    "http://127.0.0.1:${PORT}/redirect-302"

if [ -f test_output.txt ]; then
    if grep -q "hello from busybox httpd" test_output.txt; then
        echo "✓ Single 302 redirect test passed"
    else
        echo "✗ Single 302 redirect test failed - wrong content" >&2
        exit 1
    fi
else
    echo "✗ Single 302 redirect test failed - no output file" >&2
    exit 1
fi

# Test 2: Multiple redirects (chain)
echo "Test 2: Multiple 302 redirects (chain)"
"$WGET_BIN" \
    --no-config \
    --tries=1 \
    --timeout=5 \
    --max-redirect=5 \
    --output-document=redirect_test.txt \
    "http://127.0.0.1:${PORT}/redirect-chain-1"

if [ -f redirect_test.txt ]; then
    if grep -q "hello from busybox httpd" redirect_test.txt; then
        echo "✓ Multiple 302 redirects test passed"
    else
        echo "✗ Multiple 302 redirects test failed - wrong content" >&2
        exit 1
    fi
else
    echo "✗ Multiple 302 redirects test failed - no output file" >&2
    exit 1
fi

# Test 3: 302 with body (should be ignored)
echo "Test 3: 302 redirect with response body"
"$WGET_BIN" \
    --no-config \
    --tries=1 \
    --timeout=5 \
    --output-document=body_test.txt \
    "http://127.0.0.1:${PORT}/redirect-with-body"

if [ -f body_test.txt ]; then
    if grep -q "hello from busybox httpd" body_test.txt; then
        echo "✓ 302 with body test passed (body correctly ignored)"
    else
        echo "✗ 302 with body test failed - wrong content" >&2
        exit 1
    fi
else
    echo "✗ 302 with body test failed - no output file" >&2
    exit 1
fi

# Clean up test files
rm -f test_output.txt redirect_test.txt body_test.txt

echo ""
echo "✓ All HTTP 302 redirect tests passed!"
echo "The fix for redirect connection handling is working correctly."