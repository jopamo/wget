# tests/meson.build

lighttpd = find_program('lighttpd', required: false)
python3 = find_program('python3', required: false)

if python3.found()
  # Individual CLI tests
  test('cli/help',
    python3,
    args: [meson.current_source_dir() / 'test_cli_help.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'cli',
    timeout: 30,
  )

  test('cli/version',
    python3,
    args: [meson.current_source_dir() / 'test_cli_version.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'cli',
    timeout: 30,
  )

  test('cli/unknown-option',
    python3,
    args: [meson.current_source_dir() / 'test_cli_unknown_option.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'cli',
    timeout: 30,
  )

  test('cli/dns-failure',
    python3,
    args: [meson.current_source_dir() / 'test_cli_dns_failure.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'cli',
    timeout: 30,
  )

  test('cli/connection-refused',
    python3,
    args: [meson.current_source_dir() / 'test_cli_connection_refused.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'cli',
    timeout: 30,
  )

  # Individual HTTP tests
  test('http/basic-download',
    python3,
    args: [meson.current_source_dir() / 'test_http_basic_download.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/output-file',
    python3,
    args: [meson.current_source_dir() / 'test_http_output_file.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/no-clobber',
    python3,
    args: [meson.current_source_dir() / 'test_http_no_clobber.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/404',
    python3,
    args: [meson.current_source_dir() / 'test_http_404.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/post',
    python3,
    args: [meson.current_source_dir() / 'test_http_post.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/redirect-302',
    python3,
    args: [meson.current_source_dir() / 'test_http_redirect_302.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/404-handling',
    python3,
    args: [meson.current_source_dir() / 'test_http_404_handling.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/range-request',
    python3,
    args: [meson.current_source_dir() / 'test_http_range_request.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/multiple-files',
    python3,
    args: [meson.current_source_dir() / 'test_http_multiple_files.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  test('http/recursive-download',
    python3,
    args: [meson.current_source_dir() / 'test_http_recursive_download.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'http',
    timeout: 30,
  )

  # Unified lighttpd-based tests with shared server
  if lighttpd.found()
    test('lighttpd/all',
      python3,
      args: [meson.current_source_dir() / 'run_wget_lighttpd_tests.py'],
      env: {
        'WGET': meson.project_build_root() / 'src' / 'wget',
        'HTTPD_ROOT': meson.current_source_dir() / 'httpd-root',
        'LIGHTTPD': lighttpd.path(),
        'LIGHTTPD_CONF_TEMPLATE': meson.current_source_dir() / 'lighttpd.conf',
      },
      suite: ['cli', 'http', 'warc'],
      timeout: 180,
    )
  else
    message('lighttpd not found, HTTP tests disabled')
  endif

  # Python functional tests (no HTTP server required)
  test('functional-python',
    python3,
    args: [meson.current_source_dir() / 'test_functional.py'],
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
    },
    suite: 'functional',
    timeout: 60,
  )

else
  message('python3 not found, Python-based tests disabled')
endif