/* Frontend-specific globals for wget
 * src/frontend.h
 *
 * This header contains extern declarations for globals that are specific
 * to the CLI frontend and should not be defined in the core library.
 */

#pragma once

#include <stdbool.h>
#include "iri.h"
#include "hsts.h"

/* CLI program state */
extern int cleaned_up;

/* IRI dummy object for fallback behavior */
extern struct iri dummy_iri;

/* HSTS store for security policy */
extern hsts_store_t hsts_store;

/* URL counter for progress reporting */
extern int numurls;