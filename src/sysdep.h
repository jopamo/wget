/* Dirty system-dependent hacks
 * src/sysdep.h
 */

/* This file is included by wget.h.  Random .c files need not include
   it.  */

#ifndef SYSDEP_H
#define SYSDEP_H

/* Standard headers that should be available on all systems: */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>

#include <stdbool.h>
#include <limits.h>
#include <fnmatch.h>
#include "intprops.h"

#endif /* SYSDEP_H */
