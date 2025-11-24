/* Metalink checksum helpers shared between runtime and tests.
 * src/metalink_checks.h
 */

#ifndef METALINK_CHECKS_H
#define METALINK_CHECKS_H

#include "wget.h"

#ifdef HAVE_METALINK
#include <metalink/metalink_parser.h>

void wget_metalink_verify_checksums(const metalink_file_t* mfile, const char* destname, bool* size_ok, bool* hash_ok);

#endif /* HAVE_METALINK */

#endif /* METALINK_CHECKS_H */
