#!/usr/bin/env python3
"""Test recursive download functionality"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestHTTPRecursiveDownload(WgetTestBase):
    """Test recursive download functionality"""







    def test_recursive_download(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test recursive download functionality"""
        self.run_wget([
            '--no-config',
            '--recursive',
            '--level=1',
            '--no-parent',
            self.server.get_url('index.html')
        ])

        # With recursive downloads, wget creates directory structure like 127.0.0.1:PORT/
        expected_path = os.path.join(self.temp_dir, f'127.0.0.1:{self.server.port}', 'index.html')
        self.assertTrue(os.path.exists(expected_path), f"Expected file not found: {expected_path}")

if __name__ == '__main__':
    unittest.main()