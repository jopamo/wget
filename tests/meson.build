test_includes = [
  config_inc,
  include_directories('..'),
  include_directories('../src'),
]

signal_helper_sources = files(
  'signal_helpers_test.c',
  '../src/signals.c',
  '../src/evloop.c',
  '../src/xalloc.c',
)

signal_helper_test = executable(
  'signal_helpers_test',
  signal_helper_sources,
  include_directories: test_includes,
  dependencies: [libev_dep],
  install: false,
)

test('signals_libev_dispatch', signal_helper_test)

evhelpers_sources = files(
  'evhelpers_test.c',
  '../src/evhelpers.c',
  '../src/evloop.c',
  '../src/xalloc.c',
)

evhelpers_test = executable(
  'evhelpers_test',
  evhelpers_sources,
  include_directories: test_includes,
  dependencies: [libev_dep],
  install: false,
)

test('evhelpers_wait_and_sleep', evhelpers_test)
