#!/usr/bin/env python3
"""Test CLI continue functionality with partial downloads"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestCLIContinueFunctionality(WgetTestBase):
    """Test continue functionality with partial downloads"""







    def test_continue_functionality(self):
        # Skip test if server is not available
        self.skip_if_no_server()
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

if __name__ == '__main__':
    unittest.main()