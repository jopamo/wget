#!/usr/bin/env python3
"""Test CLI pipeline mode (stdout to pipe)"""
import unittest
from test_base import WgetTestBase
import subprocess
import os
import shutil
import tempfile


# Import the LighttpdServer from test_unified.py

class TestCLIPipelineMode(WgetTestBase):
    """Test pipeline mode (stdout to pipe)"""







    def test_pipeline_mode(self):
        # Skip test if server is not available
        self.skip_if_no_server()
        """Test pipeline mode (stdout to pipe)"""
        result = self.run_wget([
            '--no-config',
            '-O', '-',
            self.server.get_url('hello.txt')
        ])

        # Should have content in stdout
        self.assertGreater(len(result.stdout), 0)
        self.assertIn(b'hello from', result.stdout)

if __name__ == '__main__':
    unittest.main()