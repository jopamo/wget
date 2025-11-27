#!/usr/bin/env python3
"""Test HTTP 404 error handling"""
import unittest
import http.server
import threading
import subprocess
import os
import shutil
import tempfile

BUILD_DIR = os.environ.get('MESON_BUILD_ROOT', os.getcwd())
WGET_PATH = os.environ.get('WGET', os.path.join(BUILD_DIR, 'src', 'wget'))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
HTTPD_ROOT = os.path.join(TEST_DIR, 'httpd-root')

class TestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Silence logs

class TestHTTP404(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(('127.0.0.1', 0), TestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        os.chdir(HTTPD_ROOT)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        os.chdir(self.original_cwd)

    def get_url(self, path):
        return f"http://127.0.0.1:{self.port}/{path}"

    def run_wget(self, args, assert_exit_code=0):
        cmd = [WGET_PATH] + args
        result = subprocess.run(
            cmd,
            cwd=self.temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15
        )
        if assert_exit_code is not None:
            self.assertEqual(result.returncode, assert_exit_code,
                             f"Wget exited with {result.returncode}, expected {assert_exit_code}.\nStderr: {result.stderr.decode('utf-8', errors='replace')}")
        return result

    def test_404(self):
        """Test 404 error handling"""
        # Request non-existent file
        self.run_wget(['--no-config', self.get_url('nonexistent.txt')], assert_exit_code=None)

if __name__ == '__main__':
    unittest.main()