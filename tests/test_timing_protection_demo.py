#!/usr/bin/env python3
"""
Demo test to show improved timing protection for lighttpd startup
"""
import unittest
import os
import sys
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WgetTestBase

class TestTimingProtectionDemo(WgetTestBase):
    """Demo test showing improved timing protection"""

    def test_server_startup_timing(self):
        """Test that server startup timing is properly handled"""
        self.skip_if_no_server()

        # Verify server is responsive
        start_time = time.time()
        result = self.run_wget([
            '--no-config',
            '--output-document=timing_test.txt',
            self.server.get_url('hello.txt')
        ])

        response_time = time.time() - start_time
        print(f"Server responded in {response_time:.2f} seconds")

        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, 'timing_test.txt')))
        self.assertLess(response_time, 5.0, "Server response should be reasonably fast")

    def test_multiple_requests(self):
        """Test that server handles multiple requests reliably"""
        self.skip_if_no_server()

        # Test multiple rapid requests
        for i in range(3):
            start_time = time.time()
            result = self.run_wget([
                '--no-config',
                '--output-document', f'multi_test_{i}.txt',
                self.server.get_url('hello.txt')
            ])
            response_time = time.time() - start_time
            print(f"Request {i+1} completed in {response_time:.2f} seconds")

            self.assertTrue(os.path.exists(os.path.join(self.temp_dir, f'multi_test_{i}.txt')))

    def test_server_stability(self):
        """Test that server remains stable during test execution"""
        self.skip_if_no_server()

        # Verify server is still running after setup
        self.assertTrue(self.server.is_running(), "Server should still be running")

        # Perform multiple operations
        for i in range(5):
            result = self.run_wget([
                '--no-config',
                '--output-document', f'stability_test_{i}.txt',
                self.server.get_url('hello.txt')
            ])
            self.assertTrue(os.path.exists(os.path.join(self.temp_dir, f'stability_test_{i}.txt')))

        # Final check that server is still responsive
        self.assertTrue(self.server.is_running(), "Server should still be running after multiple requests")

if __name__ == '__main__':
    unittest.main()