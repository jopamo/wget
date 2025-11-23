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

socket_opts_sources = files(
  'socket_opts_test.c',
  '../src/socket_opts.c',
)

socket_opts_test = executable(
  'socket_opts_test',
  socket_opts_sources,
  include_directories: test_includes,
  dependencies: [],
  install: false,
)

test('socket_opts_logic', socket_opts_test)

transfer_context_sources = files(
  'transfer_context_test.c',
  'test_stubs.c',
  '../src/transfer.c',
  '../src/evloop.c',
  '../src/xalloc.c',
)

transfer_context_test = executable(
  'transfer_context_test',
  transfer_context_sources,
  include_directories: test_includes,
  dependencies: [libev_dep],
  install: false,
)

test('transfer_context_helpers', transfer_context_test)

evloop_transfer_sources = files(
  'evloop_transfer_test.c',
  'test_stubs.c',
  '../src/evloop.c',
)

evloop_transfer_test = executable(
  'evloop_transfer_test',
  evloop_transfer_sources,
  include_directories: test_includes,
  dependencies: [libev_dep],
  install: false,
)

test('evloop_transfer_tracking', evloop_transfer_test)
