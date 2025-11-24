/* Minimal host validation stubs for unit tests that need url.c helpers.
 * tests/stub_host_validation.c
 */

#include "wget.h"

#ifdef ENABLE_IPV6
#include "host.h"

bool is_valid_ipv6_address(const char* start, const char* end) {
  return start && end && start < end;
}
#endif
