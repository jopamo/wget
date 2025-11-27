#!/usr/bin/env python3
"""Test CLI dot progress indicator"""
import unittest
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WgetTestBase

class TestCLIProgressDot(WgetTestBase):
    """Test dot progress indicator"""

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

if __name__ == '__main__':
    unittest.main()