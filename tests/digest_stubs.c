/* Minimal digest helpers for unit tests that do not exercise pinning logic. */

#include "wget.h"

#include "sha256.h"

void sha256_buffer(const void* buffer WGET_ATTR_UNUSED, size_t len WGET_ATTR_UNUSED, void* resblock WGET_ATTR_UNUSED) {}
