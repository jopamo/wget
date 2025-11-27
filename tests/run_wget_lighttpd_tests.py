#!/usr/bin/env python3
"""
Unified test harness for wget lighttpd-based tests.

This script discovers and runs all test_*.py files in the tests directory,
using a shared lighttpd server instance for all tests.
"""

import os
import sys
import unittest
import logging


def main():
    """Main entry point for unified test harness"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

    # Discover and run all tests in the tests directory
    start_dir = os.path.dirname(os.path.abspath(__file__))
    loader = unittest.defaultTestLoader
    suite = loader.discover(start_dir=start_dir, pattern='test_*.py')

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()