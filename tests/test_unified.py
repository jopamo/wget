#!/usr/bin/env python3
"""
Unified wget test suite using lighttpd as web server
Replaces all busybox httpd tests with Python-based tests using lighttpd.
"""
import unittest
import subprocess
import os
import shutil
import tempfile
import sys
import time
import signal
import socket

# Locate the wget binary
BUILD_DIR = os.environ.get('MESON_BUILD_ROOT', os.getcwd())
WGET_PATH = os.environ.get('WGET', os.path.join(BUILD_DIR, 'src', 'wget'))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
HTTPD_ROOT = os.path.join(TEST_DIR, 'httpd-root')
LIGHTTPD_PATH = '/usr/bin/lighttpd'

class LighttpdServer:
    """Lighttpd server management for tests"""

    def __init__(self, port=18080):
        self.port = port
        self.process = None
        self.temp_dir = None
        self.config_path = None

    def start(self):
        """Start lighttpd server"""
        self.temp_dir = tempfile.mkdtemp()

        # Create lighttpd config
        self.config_path = os.path.join(self.temp_dir, 'lighttpd.conf')
        with open(os.path.join(TEST_DIR, 'lighttpd.conf'), 'r') as f:
            config_content = f.read()

        config_content = config_content.replace('@DOCROOT@', HTTPD_ROOT)
        config_content = config_content.replace('@PORT@', str(self.port))
        config_content = config_content.replace('@TMPDIR@', self.temp_dir)

        with open(self.config_path, 'w') as f:
            f.write(config_content)

        # Start lighttpd
        self.process = subprocess.Popen(
            [LIGHTTPD_PATH, '-D', '-f', self.config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Wait for server to start
        time.sleep(0.5)

        # Verify server is running
        if not self.is_running():
            raise RuntimeError("Lighttpd failed to start")

    def stop(self):
        """Stop lighttpd server"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def is_running(self):
        """Check if server is running"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', self.port))
                return result == 0
        except:
            return False

    def get_url(self, path):
        """Get full URL for a path"""
        return f"http://127.0.0.1:{self.port}/{path}"

class WgetTestBase(unittest.TestCase):
    """Base class for wget tests with lighttpd server"""

    @classmethod
    def setUpClass(cls):
        cls.server = LighttpdServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()

    def tearDown(self):
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

class TestHTTPBasic(WgetTestBase):
    """Basic HTTP functionality tests"""

    def test_basic_download(self):
        """Test basic file download"""
        self.run_wget([
            '--no-config',
            self.server.get_url('hello.txt')
        ])
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'hello.txt')))

    def test_404_handling(self):
        """Test 404 error handling"""
        result = self.run_wget([
            '--no-config',
            '--output-document=404_result.txt',
            self.server.get_url('nonexistent-file-12345.txt')
        ], assert_exit_code=None)

        # wget should create the file even for 404 responses
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, '404_result.txt')))

    def test_output_file(self):
        """Test custom output filename"""
        self.run_wget([
            '--no-config',
            '-O', 'custom.txt',
            self.server.get_url('hello.txt')
        ])
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'custom.txt')))
        self.assertFalse(os.path.exists(os.path.join(self.temp_dir, 'hello.txt')))

    def test_no_clobber(self):
        """Test no-clobber functionality"""
        # Create file first
        with open(os.path.join(self.temp_dir, 'hello.txt'), 'w') as f:
            f.write('original content')

        # Run with -nc
        self.run_wget([
            '--no-config',
            '-nc',
            self.server.get_url('hello.txt')
        ])

        # Content should be unchanged
        with open(os.path.join(self.temp_dir, 'hello.txt'), 'r') as f:
            self.assertEqual(f.read(), 'original content')

class TestHTTPAdvanced(WgetTestBase):
    """Advanced HTTP functionality tests"""

    def test_range_request(self):
        """Test range request functionality"""
        self.run_wget([
            '--no-config',
            '--start-pos=10',
            '--output-document=partial.txt',
            self.server.get_url('large-file.txt')
        ])

        # Verify partial file was downloaded
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'partial.txt')))

        # Check content (should start from position 10)
        with open(os.path.join(self.temp_dir, 'partial.txt'), 'rb') as f:
            content = f.read()

        # Should contain content from position 10 onward
        with open(os.path.join(HTTPD_ROOT, 'large-file.txt'), 'rb') as f:
            full_content = f.read()

        self.assertEqual(content, full_content[10:])

    def test_multiple_files(self):
        """Test downloading multiple files"""
        # Create input file with URLs
        urls_file = os.path.join(self.temp_dir, 'urls.txt')
        with open(urls_file, 'w') as f:
            f.write(f"{self.server.get_url('hello.txt')}\n")
            f.write(f"{self.server.get_url('test-data.json')}\n")

        self.run_wget([
            '--no-config',
            '--input-file', urls_file
        ])

        # Verify both files were downloaded
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'hello.txt')))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'test-data.json')))

    def test_recursive_download(self):
        """Test recursive download functionality"""
        self.run_wget([
            '--no-config',
            '--recursive',
            '--level=1',
            '--no-parent',
            self.server.get_url('index.html')
        ])

        # With recursive downloads, wget creates directory structure like 127.0.0.1:PORT/
        expected_path = os.path.join(self.temp_dir, f'127.0.0.1:{self.server.port}', 'index.html')
        self.assertTrue(os.path.exists(expected_path), f"Expected file not found: {expected_path}")

class TestCLI(WgetTestBase):
    """CLI functionality tests"""

    def test_quiet_mode(self):
        """Test quiet mode produces minimal output"""
        result = self.run_wget([
            '--no-config',
            '-q',
            self.server.get_url('hello.txt')
        ])

        # Quiet mode should produce minimal output
        self.assertEqual(len(result.stdout), 0)
        self.assertLess(len(result.stderr), 100)  # Very little stderr output

    def test_progress_dot(self):
        """Test dot progress indicator"""
        result = self.run_wget([
            '--no-config',
            '--progress=dot',
            '--output-document=dot_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'dot_test.txt')))
        # Dot mode should produce some output
        self.assertGreater(len(result.stderr), 0)

    def test_progress_bar(self):
        """Test bar progress indicator"""
        result = self.run_wget([
            '--no-config',
            '--progress=bar',
            '--output-document=bar_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'bar_test.txt')))

    def test_config_file(self):
        """Test configuration file handling"""
        # Create test wgetrc file
        wgetrc_path = os.path.join(self.temp_dir, '.wgetrc')
        with open(wgetrc_path, 'w') as f:
            f.write('user_agent = TestWget/1.0\n')

        self.run_wget([
            '--output-document=config_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'config_test.txt')))

    def test_no_config(self):
        """Test --no-config option"""
        # Create test wgetrc file that should be ignored
        wgetrc_path = os.path.join(self.temp_dir, '.wgetrc')
        with open(wgetrc_path, 'w') as f:
            f.write('user_agent = TestWget/1.0\n')

        self.run_wget([
            '--no-config',
            '--output-document=no_config_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'no_config_test.txt')))

    def test_logging(self):
        """Test logging to file"""
        self.run_wget([
            '--no-config',
            '-o', 'test_log.txt',
            '--output-document=logging_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'logging_test.txt')))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'test_log.txt')))

        # Check log file has reasonable content
        with open(os.path.join(self.temp_dir, 'test_log.txt'), 'r') as f:
            log_content = f.read()
        # Log should contain connection information
        self.assertIn('connected', log_content.lower())

    def test_pipeline_mode(self):
        """Test pipeline mode (stdout to pipe)"""
        result = self.run_wget([
            '--no-config',
            '-O', '-',
            self.server.get_url('hello.txt')
        ])

        # Should have content in stdout
        self.assertGreater(len(result.stdout), 0)
        self.assertIn(b'hello from', result.stdout)

    def test_continue_functionality(self):
        """Test continue functionality with partial downloads"""
        # Create partial file
        partial_file = os.path.join(self.temp_dir, 'continue_test.txt')
        with open(partial_file, 'w') as f:
            f.write('hello from')  # Partial content

        # Try to continue download
        self.run_wget([
            '--no-config',
            '--continue',
            '--output-document=continue_test.txt',
            self.server.get_url('hello.txt')
        ])

        # Verify file contains full content
        with open(partial_file, 'r') as f:
            content = f.read()
        self.assertIn('hello from lighttpd server', content)

class TestWARC(WgetTestBase):
    """WARC functionality tests"""

    def test_warc_basic(self):
        """Test basic WARC functionality"""
        self.run_wget([
            '--no-config',
            '--warc-file=warc_basic',
            '--output-document=warc_basic.txt',
            self.server.get_url('hello.txt')
        ])

        # Check that WARC file was created
        warc_file = None
        if os.path.exists(os.path.join(self.temp_dir, 'warc_basic.warc')):
            warc_file = os.path.join(self.temp_dir, 'warc_basic.warc')
        elif os.path.exists(os.path.join(self.temp_dir, 'warc_basic.warc.gz')):
            warc_file = os.path.join(self.temp_dir, 'warc_basic.warc.gz')

        self.assertIsNotNone(warc_file, "WARC file was not created")
        self.assertTrue(os.path.getsize(warc_file) > 0, "WARC file is empty")

    def test_warc_multi_url(self):
        """Test WARC with multiple URLs"""
        self.run_wget([
            '--no-config',
            '--warc-file=warc_multi',
            '--recursive',
            '--level=1',
            '--page-requisites',
            '--output-document=warc_multi.txt',
            self.server.get_url('hello.txt?first'),
            self.server.get_url('hello.txt?second')
        ])

        # Check that WARC file was created
        warc_file = None
        if os.path.exists(os.path.join(self.temp_dir, 'warc_multi.warc')):
            warc_file = os.path.join(self.temp_dir, 'warc_multi.warc')
        elif os.path.exists(os.path.join(self.temp_dir, 'warc_multi.warc.gz')):
            warc_file = os.path.join(self.temp_dir, 'warc_multi.warc.gz')

        self.assertIsNotNone(warc_file, "WARC file was not created")
        self.assertTrue(os.path.getsize(warc_file) > 0, "WARC file is empty")

if __name__ == '__main__':
    unittest.main()