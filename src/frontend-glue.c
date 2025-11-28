/* Frontend-specific globals definitions for wget
 * src/frontend-glue.c
 *
 * This file contains the actual definitions for globals that are specific
 * to the CLI frontend. These globals are declared as extern in frontend.h
 * and used by both the core library and frontend code.
 */

#include "frontend.h"

/* CLI program state */
int cleaned_up;

/* IRI dummy object for fallback behavior */
struct iri dummy_iri;

/* HSTS store for security policy */
hsts_store_t hsts_store;

/* URL counter for progress reporting */
int numurls;