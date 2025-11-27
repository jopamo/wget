#!/usr/bin/env python3
"""Test CLI logging functionality"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestCLILogging(WgetTestBase):
    """Test logging to file"""







    def test_logging(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test logging to file"""
        self.run_wget([
            '--no-config',
            '-o', 'test_log.txt',
            '--output-document=logging_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'logging_test.txt')))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'test_log.txt')))

        # Check log file has reasonable content
        with open(os.path.join(self.temp_dir, 'test_log.txt'), 'r') as f:
            log_content = f.read()
        # Log should contain connection information
        self.assertIn('connected', log_content.lower())

if __name__ == '__main__':
    unittest.main()