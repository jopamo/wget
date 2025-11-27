#!/usr/bin/env python3
"""Test CLI configuration file handling"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestCLIConfigFile(WgetTestBase):
    """Test configuration file handling"""







    def test_config_file(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test configuration file handling"""
        # Create test wgetrc file
        wgetrc_path = os.path.join(self.temp_dir, '.wgetrc')
        with open(wgetrc_path, 'w') as f:
            f.write('user_agent = TestWget/1.0\n')

        self.run_wget([
            '--output-document=config_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'config_test.txt')))

if __name__ == '__main__':
    unittest.main()