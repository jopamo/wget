/* src/build_info.meson.c
 * Feature summary for --version output when building with Meson.
 *
 * This is a standalone replacement for the Autotools-generated
 * build_info.c file.  It mirrors the feature list emitted by
 * build_info.pl so "wget --version" keeps its traditional output
 * without having to run Perl during Meson builds.
 */

#include "wget.h"
#include <stdio.h>

const char* compiled_features[] = {
#if defined HAVE_LIBCARES
    "+cares",
#else
    "-cares",
#endif

#if defined ENABLE_DIGEST
    "+digest",
#else
    "-digest",
#endif

#if defined HAVE_GPGME
    "+gpgme",
#else
    "-gpgme",
#endif

#if defined HAVE_SSL
    "+https",
#else
    "-https",
#endif

#if defined ENABLE_IPV6
    "+ipv6",
#else
    "-ipv6",
#endif

#if defined ENABLE_IRI
    "+iri",
#else
    "-iri",
#endif

#if SIZEOF_OFF_T >= 8 || defined WINDOWS
    "+large-file",
#else
    "-large-file",
#endif

#if defined HAVE_METALINK
    "+metalink",
#else
    "-metalink",
#endif

#if defined ENABLE_NLS
    "+nls",
#else
    "-nls",
#endif

#if defined ENABLE_NTLM
    "+ntlm",
#else
    "-ntlm",
#endif

#if defined ENABLE_OPIE
    "+opie",
#else
    "-opie",
#endif

#if defined HAVE_LIBPSL
    "+psl",
#else
    "-psl",
#endif

/* ssl choice */
#if defined HAVE_LIBSSL || defined HAVE_LIBSSL32
    "+ssl/openssl",
#elif defined HAVE_LIBGNUTLS
    "+ssl/gnutls",
#else
    "-ssl",
#endif

    /* sentinel value marking end of list */
    NULL};
