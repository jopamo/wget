src_inc = include_directories('.')

sources = [
  'base32.c',
  build_info_src,
  'connect.c',
  'convert.c',
  'cookies.c',
  'css-url.c',
  'digest.c',
  'dns_cares.c',
  'evloop.c',
  'exits.c',
  'ftp-auth.c',
  'ftp-basic.c',
  'ftp-commands.c',
  'ftp-data.c',
  'ftp-directory.c',
  'ftp-ls.c',
  'ftp-session.c',
  'ftp-types.c',
  'ftp-utils.c',
  'ftp.c',
  'hash.c',
  'host.c',
  'hsts.c',
  'html-parse.c',
  'html-url.c',
  'http-auth.c',
  'http-ntlm.c',
  'http-pconn.c',
  'http-proxy.c',
  'http-request.c',
  'http-response.c',
  'http-stat.c',
  'http-transaction.c',
  'http.c',
  'init.c',
  'log.c',
  'net_conn.c',
  'netrc.c',
  'path.c',
  'progress.c',
  'ptimer.c',
  'quoting.c',
  'recur.c',
  'res.c',
  'retr.c',
  'scheduler.c',
  'pconn.c',
  'spider.c',
  'strcase.c',
  'threading.c',
  'tmpdir.c',
  'transfer.c',
  'url.c',
  'utils.c',
  version_src,
  'warc.c',
  'xalloc.c'
]

flex_prog = find_program('flex', required: true)
css_scanner = custom_target('css_scanner',
  input: 'css.l',
  output: 'css.c',
  command: [flex_prog, '-o', '@OUTPUT@', '@INPUT@'])
sources += css_scanner

if have_iri
  sources += 'iri.c'
endif

if get_option('enable_opie')
  sources += 'ftp-opie.c'
endif

if get_option('enable_xattr')
  sources += 'xattr.c'
endif

sources += 'openssl.c'

incdirs = [src_inc, config_inc]

deps = [zlib_dep, threads_dep]
if math_dep.found()
  deps += math_dep
endif
if openssl_dep.found()
  deps += openssl_dep
endif
if idn2_dep.found()
  deps += idn2_dep
endif
if iconv_dep.length() > 0
  deps += iconv_dep
endif
if libpsl_dep.found()
  deps += libpsl_dep
endif
if libproxy_dep.found()
  deps += libproxy_dep
endif
if libcares_dep.found()
  deps += libcares_dep
endif
if libev_dep.found()
  deps += libev_dep
endif
if uuid_dep.found()
  deps += uuid_dep
endif
if pcre2_dep.found()
  deps += pcre2_dep
elif pcre_dep.found()
  deps += pcre_dep
endif

wget_lib = static_library('wget_lib', sources,
  include_directories: incdirs,
  dependencies: deps)

wget_exe = executable('wget', ['main.c', 'frontend-glue.c'],
  include_directories: incdirs,
  dependencies: deps,
  link_with: wget_lib,
  install: true)
  
# Unit tests
unit_dns = executable('unit-dns', 'unit-tests/test_dns_async.c',
  include_directories: incdirs,
  dependencies: deps,
  link_with: wget_lib)

test('unit-dns', unit_dns)

unit_evloop = executable('unit-evloop', 'unit-tests/test_evloop.c',
  include_directories: incdirs,
  dependencies: deps,
  link_with: wget_lib)

test('unit-evloop', unit_evloop)

unit_net_conn = executable('unit-net-conn', 'unit-tests/test_net_conn.c',
  include_directories: incdirs,
  dependencies: deps,
  link_with: wget_lib)

test('unit-net-conn', unit_net_conn)

unit_scheduler = executable('unit-scheduler', ['unit-tests/test_scheduler.c', 'frontend-glue.c'],
  include_directories: incdirs,
  dependencies: deps,
  link_with: wget_lib)

test('unit-scheduler', unit_scheduler)
