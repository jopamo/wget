#!/usr/bin/env python3
"""
Demo test to show improved error handling for lighttpd startup failures
"""
import unittest
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WgetTestBase

class TestErrorHandlingDemo(WgetTestBase):
    """Demo test showing graceful error handling"""

    def test_with_server_check(self):
        """Test that uses skip_if_no_server to handle server unavailability"""
        # This will skip the test if lighttpd server is not available
        self.skip_if_no_server()

        # If we get here, server is available
        result = self.run_wget([
            '--no-config',
            '--output-document=demo_test.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'demo_test.txt')))

    def test_with_assert_server(self):
        """Test that uses assert_server_available to fail if server is not available"""
        # This will raise AssertionError if server is not available
        self.assert_server_available()

        # If we get here, server is available
        result = self.run_wget([
            '--no-config',
            '--output-document=demo_test2.txt',
            self.server.get_url('hello.txt')
        ])

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'demo_test2.txt')))

    def test_server_availability_info(self):
        """Test that shows server availability status"""
        if self._server_available:
            print(f"Server is available on port {self.server.port}")
            # Perform server-dependent test
            result = self.run_wget([
                '--no-config',
                '--output-document=availability_test.txt',
                self.server.get_url('hello.txt')
            ])
            self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'availability_test.txt')))
        else:
            print("Server is not available - this test would be skipped in production")
            # In production, you would use self.skipTest() here
            # self.skipTest("Lighttpd server not available")

if __name__ == '__main__':
    unittest.main()