#!/usr/bin/env python3
"""
Unified wget test harness using lighttpd as web server.

This is the single Meson test that runs all lighttpd-based wget tests.
The lighttpd server is started once and reused across all test cases.
"""
import unittest
import os
import sys

# Import all test modules that use WgetTestBase
from test_base import WgetTestBase

# Import individual test classes from various modules
from test_http_basic_download import TestHTTPBasicDownload
from test_http_output_file import TestHTTPOutputFile
from test_http_no_clobber import TestHTTPNoClobber
from test_http_404 import TestHTTP404
from test_http_post import TestHTTPPost
from test_http_redirect_302 import TestHTTPRedirect302
from test_http_404_handling import TestHTTP404Handling
from test_http_range_request import TestHTTPRangeRequest
from test_http_multiple_files import TestHTTPMultipleFiles
from test_http_recursive_download import TestHTTPRecursiveDownload
from test_cli_quiet_mode import TestCLIQuietMode
from test_cli_progress_dot import TestCLIProgressDot
from test_cli_progress_bar import TestCLIProgressBar
from test_cli_config_file import TestCLIConfigFile
from test_cli_no_config import TestCLINoConfig
from test_cli_logging import TestCLILogging
from test_cli_pipeline_mode import TestCLIPipelineMode
from test_cli_continue_functionality import TestCLIContinueFunctionality
from test_warc_basic import TestWARCBasic
from test_warc_multi_url import TestWARCMultiURL

if __name__ == '__main__':
    # Run all tests
    unittest.main(verbosity=2)