#!/usr/bin/env python3
import unittest
import http.server
import threading
import subprocess
import os
import shutil
import tempfile
import sys

# Locate the wget binary
# Tests are run from the build directory, so we look for src/wget
BUILD_DIR = os.environ.get('MESON_BUILD_ROOT', os.getcwd())
WGET_PATH = os.environ.get('WGET', os.path.join(BUILD_DIR, 'src', 'wget'))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
HTTPD_ROOT = os.path.join(TEST_DIR, 'httpd-root')

class TestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence server logs during tests
        pass

class WgetFunctionalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a server on a random port
        cls.server = http.server.HTTPServer(('127.0.0.1', 0), TestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        
        # Switch to the httpd-root so the server serves files from there
        # But wait, SimpleHTTPRequestHandler serves CWD. 
        # We shouldn't change CWD of the whole process if possible.
        # Let's serve from HTTPD_ROOT by changing the handler directory if Python 3.7+
        # or by temporarily changing CWD in the thread? No, CWD is process global.
        # Best way: subclass and override translate_path, or just chdir for the whole test run.
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

    def run_wget(self, args):
        """Runs wget with given args, returns returncode."""
        cmd = [WGET_PATH] + args
        # Run inside temp_dir so downloads go there
        result = subprocess.run(
            cmd, 
            cwd=self.temp_dir,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            timeout=10
        )
        return result

    def test_basic_download(self):
        url = f"http://127.0.0.1:{self.port}/hello.txt"
        res = self.run_wget(['--no-config', url])
        
        self.assertEqual(res.returncode, 0, f"Wget failed. Stderr: {res.stderr.decode()}")
        
        downloaded_file = os.path.join(self.temp_dir, 'hello.txt')
        self.assertTrue(os.path.exists(downloaded_file), "hello.txt was not downloaded")
        
        original_file = os.path.join(HTTPD_ROOT, 'hello.txt')
        with open(original_file, 'rb') as f1, open(downloaded_file, 'rb') as f2:
            self.assertEqual(f1.read(), f2.read(), "Downloaded file content mismatch")

if __name__ == '__main__':
    unittest.main()
