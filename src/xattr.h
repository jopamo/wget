/* xattr.h -- POSIX Extended Attribute function mappings
 * src/xattr.h
 */

#include <stdio.h>
#include <url.h>

#ifndef _XATTR_H
#define _XATTR_H

/* Store metadata name/value attributes against fp. */
int set_file_metadata(const struct url* origin_url, const struct url* referrer_url, FILE* fp);

#if defined(__linux)
/* libc on Linux has fsetxattr (5 arguments). */
#include <sys/xattr.h>
#define USE_XATTR
#elif defined(__APPLE__)
/* libc on OS/X has fsetxattr (6 arguments). */
#include <sys/xattr.h>
#define fsetxattr(file, name, buffer, size, flags) fsetxattr((file), (name), (buffer), (size), 0, (flags))
#define USE_XATTR
#elif defined(__FreeBSD_version) && (__FreeBSD_version > 500000)
/* FreeBSD */
#include <sys/types.h>
#include <sys/extattr.h>
#define fsetxattr(file, name, buffer, size, flags) extattr_set_fd((file), EXTATTR_NAMESPACE_USER, (name), (buffer), (size))
#define USE_XATTR
#endif

#endif /* _XATTR_H */
