#!/usr/bin/env python3
"""Test downloading multiple files"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestHTTPMultipleFiles(WgetTestBase):
    """Test downloading multiple files"""



    def test_multiple_files(self):
        """Test downloading multiple files"""
        # Skip test if server is not available
        self.skip_if_no_server()
        # Create input file with URLs
        urls_file = os.path.join(self.temp_dir, 'urls.txt')
        with open(urls_file, 'w') as f:
            f.write(f"{self.server.get_url('hello.txt')}\n")
            f.write(f"{self.server.get_url('test-data.json')}\n")

        self.run_wget([
            '--no-config',
            '--input-file', urls_file
        ])

        # Verify both files were downloaded
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'hello.txt')))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'test-data.json')))

if __name__ == '__main__':
    unittest.main()