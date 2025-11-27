#!/usr/bin/env python3
"""
Base classes for wget tests with lighttpd server
"""
import unittest
import subprocess
import os
import shutil
import tempfile
import time
import signal
import socket
import logging

# Locate the wget binary
BUILD_DIR = os.environ.get('MESON_BUILD_ROOT', os.getcwd())
WGET_PATH = os.environ.get('WGET', os.path.join(BUILD_DIR, 'src', 'wget'))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
HTTPD_ROOT = os.environ.get('HTTPD_ROOT', os.path.join(TEST_DIR, 'httpd-root'))
LIGHTTPD_PATH = os.environ.get('LIGHTTPD', '/usr/bin/lighttpd')
LIGHTTPD_CONF_TEMPLATE = os.environ.get(
    'LIGHTTPD_CONF_TEMPLATE',
    os.path.join(TEST_DIR, 'lighttpd.conf')
)

# Configure logging for debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global shared server state
_shared_server = None
_shared_refcount = 0
_shared_server_error = None

class LighttpdServer:
    """Lighttpd server management for tests"""

    def __init__(self, port=18080, max_retries=3, retry_delay=2.0, max_port_attempts=10):
        self.port = port
        self.process = None
        self.temp_dir = None
        self.config_path = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_port_attempts = max_port_attempts

    def start(self):
        """Start lighttpd server with retry logic and port conflict handling"""
        original_port = self.port

        for port_attempt in range(self.max_port_attempts):
            current_port = self.port + port_attempt

            # Check if port is available before trying to start
            if self._is_port_available(current_port):
                self.port = current_port
                logger.info(f"Attempting to start lighttpd on port {self.port}")

                for retry_attempt in range(self.max_retries):
                    try:
                        self._start_single_attempt()
                        logger.info(f"Lighttpd started successfully on port {self.port}")
                        return
                    except Exception as e:
                        logger.warning(f"Lighttpd startup attempt {retry_attempt + 1} failed on port {self.port}: {e}")
                        if retry_attempt < self.max_retries - 1:
                            # Clean up before retry
                            self._cleanup()
                            # Exponential backoff
                            delay = self.retry_delay * (2 ** retry_attempt)
                            logger.info(f"Retrying in {delay} seconds...")
                            time.sleep(delay)
                        else:
                            # Final retry attempt failed for this port
                            self._cleanup()
                            logger.warning(f"Failed to start lighttpd on port {self.port} after {self.max_retries} attempts")
                            # Continue to next port
                            break
            else:
                logger.warning(f"Port {current_port} is not available, trying next port")

        # All port attempts failed
        error_msg = f"Lighttpd failed to start after trying {self.max_port_attempts} ports starting from {original_port}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    def _start_single_attempt(self):
        """Single attempt to start lighttpd server"""
        self.temp_dir = tempfile.mkdtemp()

        # Create lighttpd config from template
        self.config_path = os.path.join(self.temp_dir, 'lighttpd.conf')
        with open(LIGHTTPD_CONF_TEMPLATE, 'r') as f:
            config_content = f.read()

        config_content = config_content.replace('@DOCROOT@', HTTPD_ROOT)
        config_content = config_content.replace('@PORT@', str(self.port))
        config_content = config_content.replace('@TMPDIR@', self.temp_dir)

        with open(self.config_path, 'w') as f:
            f.write(config_content)

        # Verify lighttpd binary exists
        if not os.path.exists(LIGHTTPD_PATH):
            raise RuntimeError(f"Lighttpd binary not found at {LIGHTTPD_PATH}")

        # Start lighttpd
        self.process = subprocess.Popen(
            [LIGHTTPD_PATH, '-D', '-f', self.config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait for server to start with progressive checking
        if not self._wait_for_startup():
            # Get error output for debugging
            stdout, stderr = self._get_process_output()
            error_msg = f"Lighttpd failed to start on port {self.port}"
            if stderr:
                error_msg += f"\nStderr: {stderr.decode('utf-8', errors='replace')}"
            if stdout:
                error_msg += f"\nStdout: {stdout.decode('utf-8', errors='replace')}"
            raise RuntimeError(error_msg)

    def _wait_for_startup(self, timeout=20, check_interval=0.5):
        """Wait for lighttpd to start with timeout and progressive checking"""
        start_time = time.time()
        logger.info(f"Waiting up to {timeout} seconds for lighttpd to start on port {self.port}")

        # Progressive check intervals - more frequent at start, less frequent later
        progressive_intervals = [
            (0, 5, 0.2),    # First 5 seconds: check every 200ms
            (5, 10, 0.5),   # Next 5 seconds: check every 500ms
            (10, 20, 1.0),  # Remaining time: check every 1 second
        ]

        while time.time() - start_time < timeout:
            elapsed = time.time() - start_time

            # Determine current check interval based on elapsed time
            current_interval = check_interval
            for min_time, max_time, interval in progressive_intervals:
                if min_time <= elapsed < max_time:
                    current_interval = interval
                    break

            # Check if process is still running
            if self.process.poll() is not None:
                logger.warning(f"Lighttpd process terminated unexpectedly with return code: {self.process.returncode}")
                # Get error output for better diagnostics
                stdout, stderr = self._get_process_output()
                if stderr:
                    logger.error(f"Lighttpd stderr: {stderr.decode('utf-8', errors='replace')}")
                return False

            # Check if server is responding
            if self.is_running():
                logger.info(f"Lighttpd started successfully after {elapsed:.2f} seconds")
                return True

            # Log progress for long waits
            if elapsed > 5 and elapsed % 5 < current_interval:
                logger.info(f"Still waiting for lighttpd to start... ({elapsed:.1f}s elapsed)")

            time.sleep(current_interval)

        logger.warning(f"Lighttpd startup timeout after {timeout} seconds")
        # Get final error output for debugging
        stdout, stderr = self._get_process_output()
        if stderr:
            logger.error(f"Final lighttpd stderr: {stderr.decode('utf-8', errors='replace')}")
        return False

    def _get_process_output(self):
        """Get stdout and stderr from lighttpd process"""
        stdout, stderr = b"", b""
        if self.process:
            try:
                stdout, stderr = self.process.communicate(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
        return stdout, stderr

    def _cleanup(self):
        """Clean up temporary resources with proper shutdown timing"""
        if self.process:
            logger.info(f"Stopping lighttpd server on port {self.port}")

            # Step 1: Graceful termination
            try:
                self.process.terminate()
                self.process.wait(timeout=3)  # Give more time for graceful shutdown
            except (subprocess.TimeoutExpired, ProcessLookupError):
                logger.warning("Graceful termination failed, forcing shutdown")
                # Step 2: Forceful termination
                try:
                    self.process.kill()
                    self.process.wait(timeout=2)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    logger.error("Failed to kill lighttpd process")
            finally:
                self.process = None

        # Wait a moment to ensure port is released
        if hasattr(self, 'port'):
            time.sleep(0.5)

        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Cleaned up temp directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp dir {self.temp_dir}: {e}")
            self.temp_dir = None

    def stop(self):
        """Stop lighttpd server"""
        self._cleanup()

    def _is_port_available(self, port):
        """Check if a port is available for binding"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                # If connection succeeds, port is in use
                return result != 0
        except Exception as e:
            logger.debug(f"Port availability check failed for port {port}: {e}")
            return False

    def is_running(self):
        """Check if server is running"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', self.port))
                return result == 0
        except Exception as e:
            logger.debug(f"Socket check failed: {e}")
            return False

    def get_url(self, path):
        """Get full URL for a path"""
        return f"http://127.0.0.1:{self.port}/{path}"

class WgetTestBase(unittest.TestCase):
    """Base class for wget tests with shared lighttpd server"""

    # Class-level flag to track if server is available
    _server_available = False

    @classmethod
    def setUpClass(cls):
        """Set up shared lighttpd server with refcounting"""
        super().setUpClass()
        global _shared_server, _shared_refcount, _shared_server_error

        # Initialize shared server if not already done
        if _shared_server is None and _shared_server_error is None:
            try:
                server = LighttpdServer()
                server.start()
                _shared_server = server
                _shared_refcount = 0
                logger.info("Shared lighttpd server started for test run")
            except Exception as e:
                _shared_server_error = e
                logger.warning(f"Failed to start shared lighttpd server: {e}")

        # Assign shared server to class if available
        if _shared_server is not None and _shared_server.is_running():
            cls.server = _shared_server
            cls._server_available = True
            _shared_refcount += 1
        else:
            cls.server = None
            cls._server_available = False

    @classmethod
    def tearDownClass(cls):
        """Release reference to shared lighttpd server"""
        super().tearDownClass()
        global _shared_server, _shared_refcount

        if cls._server_available and _shared_server is not None:
            _shared_refcount -= 1
            if _shared_refcount <= 0:
                try:
                    _shared_server.stop()
                    logger.info("Shared lighttpd server stopped after last test class")
                except Exception as e:
                    logger.warning(f"Error stopping shared lighttpd server: {e}")
                _shared_server = None

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir)
        os.chdir(self.original_cwd)

    def run_wget(self, args, assert_exit_code=0, timeout=15):
        """Run wget command and return result"""
        cmd = [WGET_PATH] + args
        result = subprocess.run(
            cmd,
            cwd=self.temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        if assert_exit_code is not None:
            self.assertEqual(result.returncode, assert_exit_code,
                             f"Wget exited with {result.returncode}, expected {assert_exit_code}.\nStderr: {result.stderr.decode('utf-8', errors='replace')}")
        return result

    def skip_if_no_server(self):
        """Skip test if lighttpd server is not available"""
        if not self._server_available:
            self.skipTest("Lighttpd server not available - skipping test")

    def assert_server_available(self):
        """Assert that lighttpd server is available"""
        if not self._server_available:
            raise AssertionError("Lighttpd server is not available for this test")