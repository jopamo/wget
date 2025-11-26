# tests/meson.build

busybox = find_program('busybox', required: false)

if not busybox.found()
  message('busybox not found, HTTP functional tests disabled')
else
  httpd_wrapper = find_program(
    'httpd-wrapper.sh',
    dirs: meson.current_source_dir(),
    required: true,
  )

  httpd_wrapper_extended = find_program(
    'httpd-wrapper-extended.sh',
    dirs: meson.current_source_dir(),
    required: true,
  )

  cli_wrapper = find_program(
    'cli-wrapper.sh',
    dirs: meson.current_source_dir(),
    required: true,
  )

  # Basic test suite
  test('http/basic',
    httpd_wrapper,
    env: {
      'HTTPD': busybox.full_path(),                              # busybox binary
      'WGET': meson.project_build_root() / 'src' / 'wget',       # the built wget in build directory
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
    },
    suite: 'http',
    is_parallel: false,                                          # one httpd at a time, simple and safe
    timeout: 30,
  )

  # Extended test suite with different scenarios
  test('http/redirect',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'redirect',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  test('http/404',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': '404',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  test('http/post',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'post',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  test('http/range',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'range',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  test('http/multiple',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'multiple',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  test('http/recursive',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'recursive',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  test('http/comprehensive',
    httpd_wrapper_extended,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'comprehensive',
    },
    suite: 'http',
    is_parallel: false,
    timeout: 30,
  )

  # CLI functionality tests (don't need HTTP server)
  test('cli/help',
    cli_wrapper,
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_MODE': 'help',
    },
    suite: 'cli',
    timeout: 10,
  )

  test('cli/version',
    cli_wrapper,
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_MODE': 'version',
    },
    suite: 'cli',
    timeout: 10,
  )

  test('cli/unknown-option',
    cli_wrapper,
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_MODE': 'unknown_option',
    },
    suite: 'cli',
    timeout: 10,
  )

  # CLI tests that need HTTP server
  test('cli/no-clobber',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'no_clobber',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/output-file',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'output_file',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/quiet-mode',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'quiet_mode',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/progress-dot',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'progress_dot',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/progress-bar',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'progress_bar',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/non-interactive',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'non_interactive',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  # Error handling tests
  test('cli/dns-failure',
    cli_wrapper,
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_MODE': 'dns_failure',
    },
    suite: 'cli',
    timeout: 10,
  )

  test('cli/connection-refused',
    cli_wrapper,
    env: {
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_MODE': 'connection_refused',
    },
    suite: 'cli',
    timeout: 10,
  )

  test('cli/http-404',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'http_404',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  # Configuration tests
  test('cli/config',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'config_test',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/no-config',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'no_config_test',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/logging',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'logging_test',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/exit-code',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'exit_code_test',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/pipeline',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'pipeline_test',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/continue',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'continue_test',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  # HTTPS tests
  test('cli/https_basic',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'https_basic',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/https_cert_verify',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'https_cert_verify',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  # WARC tests
  test('cli/warc_basic',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'warc_basic',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )

  test('cli/warc_multi',
    cli_wrapper,
    env: {
      'HTTPD': busybox.full_path(),
      'WGET': meson.project_build_root() / 'src' / 'wget',
      'WGET_TEST_DOCROOT': meson.current_source_dir() / 'httpd-root',
      'WGET_TEST_MODE': 'warc_multi',
    },
    suite: 'cli',
    is_parallel: false,
    timeout: 30,
  )
endif
