#!/usr/bin/env python3
"""Test CLI --no-config option"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestCLINoConfig(WgetTestBase):
    """Test --no-config option"""







    def test_no_config(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test --no-config option"""
        # Create test wgetrc file that should be ignored
        wgetrc_path = os.path.join(self.temp_dir, '.wgetrc')
        with open(wgetrc_path, 'w') as f:
            f.write('user_agent = TestWget/1.0\n')

        self.run_wget([
            '--no-config',
            '--output-document=no_config_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'no_config_test.txt')))

if __name__ == '__main__':
    unittest.main()