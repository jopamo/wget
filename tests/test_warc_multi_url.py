#!/usr/bin/env python3
"""
Test WARC with multiple URLs
"""
import unittest
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WgetTestBase

class TestWARCMultiURL(WgetTestBase):
    """Test WARC with multiple URLs"""

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