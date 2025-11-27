#!/usr/bin/env python3
"""Test wget --version functionality"""
import unittest
import subprocess
import os
import tempfile
import shutil

BUILD_DIR = os.environ.get('MESON_BUILD_ROOT', os.getcwd())
WGET_PATH = os.environ.get('WGET', os.path.join(BUILD_DIR, 'src', 'wget'))

class TestCLIVersion(unittest.TestCase):
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

    def test_version(self):
        """Test --version option"""
        res = self.run_wget(['--version'])
        self.assertIn(b"GNU Wget", res.stdout)

if __name__ == '__main__':
    unittest.main()