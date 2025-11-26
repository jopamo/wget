#!/bin/sh
# Simple HTTP functional test harness for Meson + wget using busybox httpd

set -eu

HTTPD_BIN="${HTTPD:-busybox}"
WGET_BIN="${WGET:-./src/wget}"
DOCROOT="${WGET_TEST_DOCROOT:-\"${MESON_SOURCE_ROOT:-.}/tests/httpd-root\"}"

PORT="${WGET_TEST_PORT:-18080}"

tmpdir="$(mktemp -d)"

cleanup() {
  if [ "${HTTPD_PID:-0}" -gt 0 ] 2>/dev/null; then
    kill "${HTTPD_PID}" 2>/dev/null || true
    wait "${HTTPD_PID}" 2>/dev/null || true
  fi
  rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

# copy test files into a private docroot so tests never mutate the source tree
cp -R "${DOCROOT}/." "${tmpdir}/"

# start BusyBox httpd in foreground mode, serving tmpdir
# -f keeps it in the foreground which is good for clean signal handling
"${HTTPD_BIN}" httpd -f -p "127.0.0.1:${PORT}" -h "${tmpdir}" &
HTTPD_PID=$!

# give it a moment to bind the socket
# for most local dev this is more than enough
sleep 0.2

# basic sanity test
# fetch /hello.txt and make sure the file appears and matches the source
cd "${tmpdir}"

"${WGET_BIN}" \
  --no-config \
  --tries=1 \
  --timeout=5 \
  "http://127.0.0.1:${PORT}/hello.txt"

if ! [ -f hello.txt ]; then
  echo "error: hello.txt was not downloaded" >&2
  exit 1
fi

if ! cmp -s hello.txt "${DOCROOT}/hello.txt"; then
  echo "error: downloaded hello.txt does not match source" >&2
  exit 1
fi

# you can add more checks here as needed
# e.g. redirects, 404 handling, range requests, etc

echo "Test passed: wget successfully downloaded hello.txt from busybox httpd"
exit 0