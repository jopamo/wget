#!/usr/bin/env python3
import unittest
import http.server
import threading
import subprocess
import os
import shutil
import tempfile
import sys
import socket

# Locate the wget binary
BUILD_DIR = os.environ.get('MESON_BUILD_ROOT', os.getcwd())
WGET_PATH = os.environ.get('WGET', os.path.join(BUILD_DIR, 'src', 'wget'))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
HTTPD_ROOT = os.path.join(TEST_DIR, 'httpd-root')

class TestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Silence logs

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(length)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"POST received: " + post_data)

    def do_GET(self):
        # Custom redirects for testing
        if self.path == '/redirect-302':
            self.send_response(302)
            self.send_header('Location', '/hello.txt')
            self.end_headers()
        elif self.path == '/redirect-loop':
            self.send_response(302)
            self.send_header('Location', '/redirect-loop')
            self.end_headers()
        else:
            super().do_GET()

class WgetTestBase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        os.chdir(self.original_cwd)

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

class TestCLI(WgetTestBase):
    def test_help(self):
        res = self.run_wget(['--help'])
        self.assertIn(b"GNU Wget", res.stdout)

    def test_version(self):
        res = self.run_wget(['--version'])
        self.assertIn(b"GNU Wget", res.stdout)
        
    def test_unknown_option(self):
        self.run_wget(['--this-option-does-not-exist'], assert_exit_code=2)

    def test_dns_failure(self):
        # Domain that definitely shouldn't exist
        self.run_wget(['http://this-domain-should-not-exist.invalid/'], assert_exit_code=4)

    def test_connection_refused(self):
        # Find a free port and assume nothing is listening on it (since we didn't bind it)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        # Socket closed immediately
        
        self.run_wget([f'http://127.0.0.1:{port}/'], assert_exit_code=4)

class TestHTTP(WgetTestBase):
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

    def get_url(self, path):
        return f"http://127.0.0.1:{self.port}/{path}"

    def test_basic_download(self):
        self.run_wget(['--no-config', self.get_url('hello.txt')])
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'hello.txt')))

    def test_404(self):
        # Request non-existent file
        self.run_wget(['--no-config', self.get_url('nonexistent.txt')], assert_exit_code=None)

    def test_output_file(self):
        self.run_wget(['--no-config', '-O', 'custom.txt', self.get_url('hello.txt')])
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'custom.txt')))
        self.assertFalse(os.path.exists(os.path.join(self.temp_dir, 'hello.txt')))

    def test_no_clobber(self):
        # Create file first
        with open(os.path.join(self.temp_dir, 'hello.txt'), 'w') as f:
            f.write('original content')
        
        # Run with -nc
        self.run_wget(['--no-config', '-nc', self.get_url('hello.txt')])
        
        # Content should be unchanged
        with open(os.path.join(self.temp_dir, 'hello.txt'), 'r') as f:
            self.assertEqual(f.read(), 'original content')

    def test_post(self):
        # Basic POST test
        url = self.get_url('post-test')
        data = "key=value"
        res = self.run_wget(['--no-config', '--post-data', data, url, '-O', '-'])
        self.assertIn(b"POST received: key=value", res.stdout)

    def test_redirect_302(self):
        self.run_wget(['--no-config', self.get_url('redirect-302')])
        # Wget follows redirects but saves to filename based on original URL
        # The content from hello.txt should be saved to redirect-302 file
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'redirect-302')))

if __name__ == '__main__':
    unittest.main()
