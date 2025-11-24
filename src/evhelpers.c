/* Helper glue translating sockets and timers into libev primitives
 * src/evhelpers.c
 */

#include "wget.h"

#include <errno.h>
#include <ev.h>
#include <stdbool.h>

#include "evhelpers.h"
#include "evloop.h"
#include "threading.h"
