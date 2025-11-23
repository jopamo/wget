project('wget', 'c', version: '1.25.0', default_options: ['warning_level=2', 'c_std=gnu11'])

cc = meson.get_compiler('c')
add_project_arguments('-D_GNU_SOURCE', '-D_FILE_OFFSET_BITS=64', language: 'c')

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', 'wget')
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('SYSTEM_WGETRC', get_option('system_wgetrc'))
conf.set_quoted('LOCALEDIR', get_option('locale_dir'))
conf.set_quoted('OS_TYPE', host_machine.system())
conf.set('SIZEOF_OFF_T', cc.sizeof('off_t'))

metalink_opt = get_option('metalink')
cookies_opt = get_option('cookies')
psl_opt = get_option('psl')
proxies_opt = get_option('proxies')
idn2_opt = get_option('idn2')
compression_opt = get_option('compression')

if not cookies_opt.disabled()
  conf.set('ENABLE_COOKIES', 1)
endif

conf.set('ENABLE_DIGEST', 1)
conf.set('ENABLE_IPV6', 1)
conf.set('ENABLE_NTLM', 1)
if get_option('enable_debug_logging')
  conf.set('ENABLE_DEBUG', 1)
endif
if get_option('enable_opie')
  conf.set('ENABLE_OPIE', 1)
endif
if get_option('enable_xattr')
  conf.set('ENABLE_XATTR', 1)
endif

zlib_dep = dependency('zlib', required: true)
if not compression_opt.disabled()
  conf.set('ENABLE_COMPRESSION', 1)
endif
threads_dep = dependency('threads')
math_dep = cc.find_library('m', required: false)

if psl_opt.disabled()
  libpsl_dep = disabler()
else
  libpsl_dep = dependency('libpsl', required: psl_opt.enabled())
endif
if proxies_opt.disabled()
  libproxy_dep = disabler()
else
  libproxy_dep = dependency('libproxy-1.0', required: proxies_opt.enabled())
  if not libproxy_dep.found()
    libproxy_dep = dependency('libproxy', required: proxies_opt.enabled())
  endif
endif
libcares_dep = dependency('libcares', required: true)
libev_dep = dependency('libev', required: true)
uuid_dep = dependency('uuid', required: false)

pcre2_dep = dependency('libpcre2-8', required: false)
pcre_dep = dependency('libpcre', required: not pcre2_dep.found())

if idn2_opt.disabled()
  idn2_dep = disabler()
else
  idn2_dep = dependency('libidn2', required: idn2_opt.enabled())
endif
have_iconv = cc.has_function('iconv_open', prefix: '#include <iconv.h>')
iconv_dep = []
if not have_iconv
  iconv_lib = cc.find_library('iconv', required: false)
  if iconv_lib.found() and cc.has_function('iconv_open', prefix: '#include <iconv.h>', dependencies: iconv_lib)
    have_iconv = true
    iconv_dep = [iconv_lib]
  endif
endif

have_iri = have_iconv and idn2_dep.found()
if have_iri
  conf.set('ENABLE_IRI', 1)
endif
if have_iconv
  conf.set('HAVE_ICONV', 1)
endif
iconv_const = ''
if have_iconv
  iconv_const_test = '''
    #include <iconv.h>
    int main(void) {
      iconv_t cd = (iconv_t)0;
      const char *inbuf = 0;
      size_t inbytes = 0;
      char *outbuf = 0;
      size_t outbytes = 0;
      (void)iconv(cd, &inbuf, &inbytes, &outbuf, &outbytes);
      return 0;
    }
  '''
  if cc.compiles(iconv_const_test, name: 'iconv const qualifier')
    iconv_const = 'const'
  endif
endif
conf.set('ICONV_CONST', iconv_const)
if idn2_dep.found()
  conf.set('HAVE_LIBIDN2', 1)
endif

if not have_iri and not idn2_opt.disabled()
  message('Building without IRI support (requires iconv + libidn2).')
endif

openssl_dep = dependency('openssl', required: true)
have_rand_egd = false

if not openssl_dep.found()
  error('OpenSSL dependency was not found; it is required for TLS and digest helpers')
endif

conf.set('HAVE_LIBSSL', 1)
have_rand_egd = cc.has_function('RAND_egd', prefix: '#include <openssl/rand.h>', dependencies: openssl_dep)

if have_rand_egd
  conf.set('HAVE_RAND_EGD', 1)
endif

conf.set('HAVE_LIBZ', 1)
if libpsl_dep.found()
  conf.set('HAVE_LIBPSL', 1)
endif
if libproxy_dep.found()
  conf.set('HAVE_LIBPROXY', 1)
endif
if libcares_dep.found()
  conf.set('HAVE_LIBCARES', 1)
endif
if libev_dep.found()
  conf.set('HAVE_LIBEV', 1)
endif
if uuid_dep.found()
  conf.set('HAVE_LIBUUID', 1)
endif
if pcre2_dep.found()
  conf.set('HAVE_LIBPCRE2', 1)
endif
if pcre_dep.found()
  conf.set('HAVE_LIBPCRE', 1)
endif

if metalink_opt.disabled()
  metalink_dep = disabler()
  gpgme_dep = disabler()
else
  metalink_dep = dependency('libmetalink', required: metalink_opt.enabled())
  if metalink_dep.found()
    conf.set('HAVE_METALINK', 1)
    gpgme_dep = dependency('gpgme', required: false)
    if gpgme_dep.found()
      conf.set('HAVE_GPGME', 1)
    endif
  else
    gpgme_dep = disabler()
  endif
endif

if cc.has_header('pthread.h')
  conf.set('HAVE_PTHREAD_H', 1)
endif
if cc.has_header('pwd.h')
  conf.set('HAVE_PWD_H', 1)
endif
if cc.has_function('drand48', prefix: '#include <stdlib.h>')
  conf.set('HAVE_DRAND48', 1)
endif
if cc.has_function('random', prefix: '#include <stdlib.h>')
  conf.set('HAVE_RANDOM', 1)
endif
if cc.has_function('sleep', prefix: '#include <unistd.h>')
  conf.set('HAVE_SLEEP', 1)
endif
if cc.has_function('usleep', prefix: '#include <unistd.h>')
  conf.set('HAVE_USLEEP', 1)
endif
if cc.has_function('nanosleep', prefix: '#include <time.h>')
  conf.set('HAVE_NANOSLEEP', 1)
endif
if cc.has_function('fseeko', prefix: '#include <stdio.h>')
  conf.set('HAVE_FSEEKO', 1)
endif
if cc.has_function('ftello', prefix: '#include <stdio.h>')
  conf.set('HAVE_FTELLO', 1)
endif
if cc.has_function('fmemopen', prefix: '#include <stdio.h>')
  conf.set('HAVE_FMEMOPEN', 1)
endif
if cc.has_function('mmap', prefix: '#include <sys/mman.h>')
  conf.set('HAVE_MMAP', 1)
endif
if cc.has_function('sigsetjmp', prefix: '#include <setjmp.h>')
  conf.set('HAVE_SIGSETJMP', 1)
endif
if cc.has_function('sigblock', prefix: '#include <signal.h>')
  conf.set('HAVE_SIGBLOCK', 1)
endif
if cc.has_function('wcwidth', prefix: '#include <wchar.h>')
  conf.set('HAVE_WCWIDTH', 1)
endif
if cc.has_function('mbtowc', prefix: '#include <stdlib.h>')
  conf.set('HAVE_MBTOWC', 1)
endif
if cc.has_function('isatty', prefix: '#include <unistd.h>')
  conf.set('HAVE_ISATTY', 1)
endif
if cc.has_header_symbol('netdb.h', 'h_errno', prefix: '#include <netdb.h>')
  conf.set('HAVE_DECL_H_ERRNO', 1)
endif
if cc.has_type('intptr_t', prefix: '#include <stdint.h>')
  conf.set('HAVE_INTPTR_T', 1)
endif
if cc.has_function('vasprintf', prefix: '#include <stdio.h>')
  conf.set('HAVE_VASPRINTF', 1)
endif
if cc.has_function('strlcpy', prefix: '#include <string.h>')
  conf.set('HAVE_STRLCPY', 1)
endif
if cc.has_type('struct sockaddr_storage', prefix: '#include <sys/types.h>\n#include <sys/socket.h>')
  conf.set('HAVE_STRUCT_SOCKADDR_STORAGE', 1)
endif

if not cc.has_header_symbol('fcntl.h', 'O_BINARY')
  conf.set('O_BINARY', 0)
endif

compilation_string = '@0@ @1@'.format(cc.get_id(), cc.version())
link_components = []
link_components += ['zlib']
if threads_dep.found()
  link_components += ['threads']
endif
if math_dep.found()
  link_components += ['libm']
endif
if openssl_dep.found()
  link_components += ['openssl']
endif
if idn2_dep.found()
  link_components += ['libidn2']
endif
if have_iconv
  link_components += ['iconv']
endif
if libpsl_dep.found()
  link_components += ['libpsl']
endif
if libproxy_dep.found()
  link_components += ['libproxy']
endif
if libcares_dep.found()
  link_components += ['libcares']
endif
if libev_dep.found()
  link_components += ['libev']
endif
if uuid_dep.found()
  link_components += ['libuuid']
endif
if pcre2_dep.found()
  link_components += ['libpcre2']
elif pcre_dep.found()
  link_components += ['libpcre']
endif
if metalink_dep.found()
  link_components += ['libmetalink']
endif
if gpgme_dep.found()
  link_components += ['gpgme']
endif
link_components += ['tls=openssl']
link_string = ''
if link_components.length() > 0
  link_string = 'deps: ' + ' '.join(link_components)
endif

build_info_src = configure_file(
  input: 'src/build_info.meson.c',
  output: 'build_info.c',
  copy: true)

version_conf = configuration_data()
version_conf.set_quoted('VERSION_STRING', meson.project_version())
version_conf.set_quoted('COMPILATION_STRING', compilation_string)
version_conf.set_quoted('LINK_STRING', link_string)
version_src = configure_file(
  input: 'src/version.c.meson.in',
  output: 'version.c',
  configuration: version_conf)

configure_file(
  output: 'config.h',
  configuration: conf)

config_inc = include_directories('.')

subdir('src')
