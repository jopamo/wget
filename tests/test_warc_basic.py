#!/usr/bin/env python3
"""Test WARC basic functionality"""
import unittest
import subprocess
import os
import shutil
import tempfile

from test_base import WgetTestBase

class TestWARCBasic(WgetTestBase):
    """Test basic WARC functionality"""







    def test_warc_basic(self):
        # Skip test if server is not available
        self.skip_if_no_server()
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

if __name__ == '__main__':
    unittest.main()