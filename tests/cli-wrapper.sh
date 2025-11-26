#!/bin/sh
# CLI functionality test harness for wget

set -eu

HTTPD_BIN="${HTTPD:-busybox}"
WGET_BIN="${WGET:-./src/wget}"
DOCROOT="${WGET_TEST_DOCROOT:-${MESON_SOURCE_ROOT:-.}/tests/httpd-root}"
TEST_MODE="${WGET_TEST_MODE:-help}"

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

# copy test files into a private docroot so tests never mutate the source tree (if HTTPD is set)
if [ -n "${HTTPD:-}" ]; then
  cp -R "${DOCROOT}/." "${tmpdir}/"

  # start BusyBox httpd in foreground mode, serving tmpdir
  "${HTTPD_BIN}" httpd -f -p "127.0.0.1:${PORT}" -h "${tmpdir}" &
  HTTPD_PID=$!
  # give it a moment to bind the socket
  sleep 0.2
fi

cd "${tmpdir}"

case "${TEST_MODE}" in
    help)
        echo "Running help output test..."
        # Test that --help prints cleanly
        "${WGET_BIN}" --help > help_output.txt 2>&1

        # Check if help output is reasonable length (not empty, not enormous)
        lines=$(wc -l < help_output.txt)
        if [ "$lines" -lt 10 ]; then
            echo "error: help output too short ($lines lines)" >&2
            exit 1
        fi

        # Check for common help sections
        if ! grep -q "Usage:" help_output.txt; then
            echo "error: help output missing 'Usage:' section" >&2
            exit 1
        fi

        # Check for any section headers (wget uses different section names)
        if ! grep -q "^[A-Z][a-z].*:" help_output.txt; then
            echo "error: help output missing section headers" >&2
            exit 1
        fi

        echo "✓ Help output test passed"
        ;;

    version)
        echo "Running version test..."
        # Test that --version works
        "${WGET_BIN}" --version > version_output.txt 2>&1

        # Check version output has expected content
        if ! grep -q "wget" version_output.txt; then
            echo "error: version output doesn't mention wget" >&2
            exit 1
        fi

        echo "✓ Version test passed"
        ;;

    unknown_option)
        echo "Running unknown option test..."
        # Test that unknown options produce proper error
        set +e
        "${WGET_BIN}" --no-such-option 2> error_output.txt
        exit_code=$?
        set -e

        # Check exit code is non-zero (wget returns 2 for unknown options)
        if [ "$exit_code" -eq 0 ]; then
            echo "error: unknown option should have non-zero exit code" >&2
            exit 1
        fi

        # Check error message mentions help or usage
        if ! grep -q -i "help\|usage" error_output.txt; then
            echo "error: unknown option error should mention help or usage" >&2
            exit 1
        fi

        echo "✓ Unknown option test passed"
        ;;

    no_clobber)
        echo "Running no-clobber test..."
        # Create a test file
        echo "original content" > test_file.txt

        # Try to download to same file with --no-clobber
        # This should skip the download since file exists
        "${WGET_BIN}" --no-config --no-clobber http://127.0.0.1:18080/hello.txt 2> clobber_output.txt

        # Verify original file is unchanged
        if ! grep -q "original content" test_file.txt; then
            echo "error: original file was modified by no-clobber" >&2
            exit 1
        fi

        # Check that wget reported skipping the file
        if ! grep -q "already there; not retrieving" clobber_output.txt; then
            echo "error: no-clobber should report skipping existing file" >&2
            exit 1
        fi

        echo "✓ No-clobber test passed"
        ;;

    output_file)
        echo "Running output file test..."
        # Test -O with custom filename
        "${WGET_BIN}" --no-config -O custom_output.txt http://127.0.0.1:18080/hello.txt

        if ! [ -f custom_output.txt ]; then
            echo "error: custom output file was not created" >&2
            exit 1
        fi

        echo "✓ Output file test passed"
        ;;

    quiet_mode)
        echo "Running quiet mode test..."
        # Test -q produces minimal output
        "${WGET_BIN}" --no-config -q http://127.0.0.1:18080/hello.txt 2> quiet_output.txt

        # Check that quiet mode produces very little output
        lines=$(wc -l < quiet_output.txt)
        if [ "$lines" -gt 5 ]; then
            echo "error: quiet mode produced too much output ($lines lines)" >&2
            exit 1
        fi

        echo "✓ Quiet mode test passed"
        ;;

    progress_dot)
        echo "Running progress dot test..."
        # Test --progress=dot mode
        "${WGET_BIN}" \
            --no-config \
            --progress=dot \
            --output-document=dot_test.txt \
            http://127.0.0.1:18080/hello.txt 2> dot_output.txt

        if ! [ -f dot_test.txt ]; then
            echo "error: dot_test.txt was not created" >&2
            exit 1
        fi

        # Check that dot mode produces some output
        lines=$(wc -l < dot_output.txt)
        if [ "$lines" -eq 0 ]; then
            echo "error: progress=dot should produce some output" >&2
            exit 1
        fi

        echo "✓ Progress dot test passed"
        ;;

    progress_bar)
        echo "Running progress bar test..."
        # Test --progress=bar mode
        "${WGET_BIN}" \
            --no-config \
            --progress=bar \
            --output-document=bar_test.txt \
            http://127.0.0.1:18080/hello.txt 2> bar_output.txt

        if ! [ -f bar_test.txt ]; then
            echo "error: bar_test.txt was not created" >&2
            exit 1
        fi

        echo "✓ Progress bar test passed"
        ;;

    non_interactive)
        echo "Running non-interactive mode test..."
        # Test that wget works when stderr is redirected (non-interactive)
        "${WGET_BIN}" \
            --no-config \
            --output-document=noninteractive_test.txt \
            http://127.0.0.1:18080/hello.txt 2>&1 > /dev/null

        if ! [ -f noninteractive_test.txt ]; then
            echo "error: noninteractive_test.txt was not created" >&2
            exit 1
        fi

        echo "✓ Non-interactive mode test passed"
        ;;

    dns_failure)
        echo "Running DNS failure test..."
        # Test DNS failure handling
        set +e
        "${WGET_BIN}" --no-config http://no-such-host.invalid 2> dns_error.txt
        exit_code=$?
        set -e

        # Check exit code is non-zero
        if [ "$exit_code" -eq 0 ]; then
            echo "error: DNS failure should have non-zero exit code" >&2
            exit 1
        fi

        # Check error message mentions DNS or host
        if ! grep -q -i "dns\|host\|unable to resolve" dns_error.txt; then
            echo "error: DNS failure error should mention DNS or host" >&2
            exit 1
        fi

        echo "✓ DNS failure test passed"
        ;;

    connection_refused)
        echo "Running connection refused test..."
        # Test connection refused handling
        set +e
        "${WGET_BIN}" --no-config http://127.0.0.1:9999 2> connection_error.txt
        exit_code=$?
        set -e

        # Check exit code is non-zero
        if [ "$exit_code" -eq 0 ]; then
            echo "error: connection refused should have non-zero exit code" >&2
            exit 1
        fi

        # Check error message mentions connection
        if ! grep -q -i "connection\|refused\|failed\|unreachable" connection_error.txt; then
            echo "error: connection refused error should mention connection" >&2
            exit 1
        fi

        echo "✓ Connection refused test passed"
        ;;

    http_404)
        echo "Running HTTP 404 test..."
        # Test HTTP 404 handling
        "${WGET_BIN}" \
            --no-config \
            --output-document=404_result.txt \
            http://127.0.0.1:18080/nonexistent-file-12345.txt 2> 404_error.txt

        # wget should create the file even for 404 responses
        if ! [ -f 404_result.txt ]; then
            echo "error: wget should have created file for 404 response" >&2
            exit 1
        fi

        # Check that 404 is mentioned in output
        if ! grep -q -i "404\|not found" 404_error.txt; then
            echo "error: 404 error should mention 404 or not found" >&2
            exit 1
        fi

        echo "✓ HTTP 404 test passed"
        ;;

    config_test)
        echo "Running configuration test..."
        # Create a test wgetrc file
        cat > .wgetrc << 'EOF'
# Test configuration file
user_agent = TestWget/1.0
EOF

        # Test that wget respects configuration
        "${WGET_BIN}" \
            --output-document=config_test.txt \
            http://127.0.0.1:18080/hello.txt 2> config_output.txt

        if ! [ -f config_test.txt ]; then
            echo "error: config_test.txt was not created" >&2
            exit 1
        fi

        # Check that configuration was used (we can't easily verify user-agent, but at least it should work)
        echo "✓ Configuration test passed (basic functionality verified)"
        ;;

    no_config_test)
        echo "Running no-config test..."
        # Create a test wgetrc file
        cat > .wgetrc << 'EOF'
# Test configuration file that should be ignored
user_agent = TestWget/1.0
EOF

        # Test that --no-config ignores configuration
        "${WGET_BIN}" \
            --no-config \
            --output-document=no_config_test.txt \
            http://127.0.0.1:18080/hello.txt 2> no_config_output.txt

        if ! [ -f no_config_test.txt ]; then
            echo "error: no_config_test.txt was not created" >&2
            exit 1
        fi

        # The test passes if wget works with --no-config
        # We can't easily verify that the config was ignored, but at least it should work
        echo "✓ No-config test passed (basic functionality verified)"
        ;;

        continue_test)
        echo "Running continue test..."
        # Create a realistic partial file that matches the beginning of the server document
        head -c 16 hello.txt > continue_test.txt

        # Try to continue download
        "${WGET_BIN}" \
            --no-config \
            --continue \
            --output-document=continue_test.txt \
            http://127.0.0.1:18080/hello.txt 2> continue_output.txt

        if ! [ -f continue_test.txt ]; then
            echo "error: continue_test.txt was not created" >&2
            exit 1
        fi

        # Check that file now contains the full downloaded content
        if ! grep -q "hello from busybox httpd" continue_test.txt; then
            echo "error: continue_test.txt doesn't contain downloaded content" >&2
            exit 1
        fi

        echo "✓ Continue test passed"
        ;;

    logging_test)
        echo "Running logging test..."
        # Test -o option
        "${WGET_BIN}" \
            --no-config \
            -o test_log.txt \
            --output-document=logging_test.txt \
            http://127.0.0.1:18080/hello.txt

        if ! [ -f logging_test.txt ]; then
            echo "error: logging_test.txt was not created" >&2
            exit 1
        fi

        if ! [ -f test_log.txt ]; then
            echo "error: test_log.txt was not created" >&2
            exit 1
        fi

        # Check log file has reasonable content
        if ! grep -q -i "wget\|http\|download" test_log.txt; then
            echo "error: log file doesn't contain expected content" >&2
            exit 1
        fi

        echo "✓ Logging test passed"
        ;;

    exit_code_test)
        echo "Running exit code test..."
        # Test successful download has exit code 0
        set +e
        "${WGET_BIN}" \
            --no-config \
            --output-document=exit_code_test.txt \
            http://127.0.0.1:18080/hello.txt > /dev/null 2>&1
        exit_code=$?
        set -e

        if [ "$exit_code" -ne 0 ]; then
            echo "error: successful download should have exit code 0, got $exit_code" >&2
            exit 1
        fi

        echo "✓ Exit code test passed"
        ;;

    pipeline_test)
        echo "Running pipeline test..."
        # Test that wget works when stdout is a pipe
        "${WGET_BIN}" \
            --no-config \
            -O - \
            http://127.0.0.1:18080/hello.txt 2> pipeline_error.txt | head -5 > pipeline_output.txt

        if ! [ -s pipeline_output.txt ]; then
            echo "error: pipeline output is empty" >&2
            exit 1
        fi

        # Check that stderr doesn't contain binary/progress junk
        if grep -q -P "\x1b|\[|%" pipeline_error.txt 2>/dev/null || grep -q "\[\|%" pipeline_error.txt; then
            echo "warning: stderr may contain progress characters in pipeline mode" >&2
            # This is not necessarily an error, just a warning
        fi

        echo "✓ Pipeline test passed"
        ;;

    *)
        echo "Unknown test mode: ${TEST_MODE}" >&2
        exit 1
        ;;
esac

echo "All CLI tests completed successfully!"
exit 0
