#!/usr/bin/env python3
"""
Test bar progress indicator
"""
import unittest
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WgetTestBase

class TestCLIProgressBar(WgetTestBase):
    """Test bar progress indicator"""

    def test_progress_bar(self):
        """Test bar progress indicator"""
        result = self.run_wget([
            '--no-config',
            '--progress=bar',
            '--output-document=bar_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'bar_test.txt')))

if __name__ == '__main__':
    unittest.main()