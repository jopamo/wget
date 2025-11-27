#!/usr/bin/env python3
"""
Test 404 error handling functionality
"""
import unittest
import subprocess
import os
import shutil
import tempfile
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WgetTestBase, WgetTestBase

class TestHTTP404Handling(WgetTestBase):
    """Test 404 error handling"""





    def test_404_handling(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test 404 error handling"""
        result = self.run_wget([
            '--no-config',
            '--output-document=404_result.txt',
            self.server.get_url('nonexistent-file-12345.txt')
        ], assert_exit_code=None)

        # wget should create the file even for 404 responses
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, '404_result.txt')))

if __name__ == '__main__':
    unittest.main()