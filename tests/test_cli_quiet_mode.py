#!/usr/bin/env python3
"""Test CLI quiet mode functionality"""
import unittest
import subprocess
import os
import shutil
import tempfile

from test_base import WgetTestBase

class TestCLIQuietMode(WgetTestBase):
    """Test quiet mode functionality"""

    def test_quiet_mode(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test quiet mode produces minimal output"""
        result = self.run_wget([
            '--no-config',
            '-q',
            self.server.get_url('hello.txt')
        ])

        # Quiet mode should produce minimal output
        self.assertEqual(len(result.stdout), 0)
        self.assertLess(len(result.stderr), 100)  # Very little stderr output

if __name__ == '__main__':
    unittest.main()