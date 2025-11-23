/* Minimal dirname/basename helpers.
 * src/dirname.h
 */

#ifndef WGET_DIRNAME_H
#define WGET_DIRNAME_H

char* base_name(const char* path);
char* dir_name(const char* path);
char* canonicalize_path(const char* path);

#endif /* WGET_DIRNAME_H */
