/* HTTP header utilities.
 * src/http-header.c
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.
 *
 * This file is part of GNU Wget.
 *
 * GNU Wget is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wget.h"

#include <string.h>
#include <time.h>
#include <locale.h>
#include <stdbool.h>

#include "http-header.h"

#include "utils.h"

#include "c-ctype.h"

#include "xalloc.h"

#include "url.h"

#include "c-strcase.h"

#define NOT_RFC2231 0

#define RFC2231_NOENCODING 1

#define RFC2231_ENCODING 2

/* extract_param extracts the parameter name into NAME.

   However, if the parameter name is in RFC2231 format then

   this function adjusts NAME by stripping of the trailing

   characters that are not part of the name but are present to

   indicate the presence of encoding information in the value

   or a fragment of a long parameter value

*/

static int modify_param_name(param_token* name) {
  const char* delim1 = memchr(name->b, '*', name->e - name->b);

  const char* delim2 = memrchr(name->b, '*', name->e - name->b);

  int result;

  if (delim1 == NULL) {
    result = NOT_RFC2231;
  }

  else if (delim1 == delim2) {
    if ((name->e - 1) == delim1) {
      result = RFC2231_ENCODING;
    }

    else {
      result = RFC2231_NOENCODING;
    }

    name->e = delim1;
  }

  else {
    name->e = delim1;

    result = RFC2231_ENCODING;
  }

  return result;
}

/* extract_param extract the parameter value into VALUE.

   Like modify_param_name this function modifies VALUE by

   stripping off the encoding information from the actual value

*/

static void modify_param_value(param_token* value, int encoding_type) {
  if (encoding_type == RFC2231_ENCODING) {
    const char* delim = memrchr(value->b, '\'', value->e - value->b);

    if (delim != NULL) {
      value->b = (delim + 1);
    }
  }
}

/* Extract a parameter from the string (typically an HTTP header) at

   **SOURCE and advance SOURCE to the next parameter.  Return false

   when there are no more parameters to extract.  The name of the

   parameter is returned in NAME, and the value in VALUE.  If the

   parameter has no value, the token's value is zeroed out.



   For example, if *SOURCE points to the string "attachment;

   filename=\"foo bar\"", the first call to this function will return

   the token named "attachment" and no value, and the second call will

   return the token named "filename" and value "foo bar".  The third

   call will return false, indicating no more valid tokens.



   is_url_encoded is an out parameter. If not NULL, a boolean value will be

   stored into it, letting the caller know whether or not the extracted value is

   URL-encoded. The caller can then decode it with url_unescape(), which however

   performs decoding in-place. URL-encoding is used by RFC 2231 to support

   non-US-ASCII characters in HTTP header values.  */

bool extract_param(const char** source, param_token* name, param_token* value, char separator, bool* is_url_encoded) {
  const char* p = *source;

  int param_type;

  if (is_url_encoded)

    *is_url_encoded = false; /* initializing the out parameter */

  while (c_isspace(*p))

    ++p;

  if (!*p) {
    *source = p;

    return false; /* no error; nothing more to extract */
  }

  /* Extract name. */

  name->b = p;

  while (*p && !c_isspace(*p) && *p != '=' && *p != separator)

    ++p;

  name->e = p;

  if (name->b == name->e)

    return false; /* empty name: error */

  while (c_isspace(*p))

    ++p;

  if (*p == separator || !*p) /* no value */

  {
    xzero(*value);

    if (*p == separator)

      ++p;

    *source = p;

    return true;
  }

  if (*p != '=')

    return false; /* error */

  /* *p is '=', extract value */

  ++p;

  while (c_isspace(*p))

    ++p;

  if (*p == '"') /* quoted */

  {
    value->b = ++p;

    while (*p && *p != '"')

      ++p;

    if (!*p)

      return false;

    value->e = p++;

    /* Currently at closing quote; find the end of param. */

    while (c_isspace(*p))

      ++p;

    while (*p && *p != separator)

      ++p;

    if (*p == separator)

      ++p;

    else if (*p)

      /* garbage after closed quote, e.g. foo="bar"baz */

      return false;
  }

  else /* unquoted */

  {
    value->b = p;

    while (*p && *p != separator)

      ++p;

    value->e = p;

    while (value->e != value->b && c_isspace(value->e[-1]))

      --value->e;

    if (*p == separator)

      ++p;
  }

  *source = p;

  param_type = modify_param_name(name);

  if (param_type != NOT_RFC2231) {
    if (param_type == RFC2231_ENCODING && is_url_encoded)

      *is_url_encoded = true;

    modify_param_value(value, param_type);
  }

  return true;
}

#undef NOT_RFC2231

#undef RFC2231_NOENCODING

#undef RFC2231_ENCODING

/* Check whether the result of strptime() indicates success.

   strptime() returns the pointer to how far it got to in the string.

   The processing has been successful if the string is at `GMT' or

   `+X', or at the end of the string.



   In extended regexp parlance, the function returns 1 if P matches

   "^ *(GMT|[+-][0-9]|$)", 0 otherwise.  P being NULL (which strptime

   can return) is considered a failure and 0 is returned.  */

static bool check_end(const char* p) {
  if (!p)

    return false;

  while (c_isspace(*p))

    ++p;

  if (!*p || (p[0] == 'G' && p[1] == 'M' && p[2] == 'T') || ((p[0] == '+' || p[0] == '-') && c_isdigit(p[1])))

    return true;

  else

    return false;
}

/* Convert the textual specification of time in TIME_STRING to the

   number of seconds since the Epoch.



   TIME_STRING can be in any of the three formats RFC2616 allows the

   HTTP servers to emit -- RFC1123-date, RFC850-date or asctime-date,

   as well as the time format used in the Set-Cookie header.

   Timezones are ignored, and should be GMT.



   Return the computed time_t representation, or -1 if the conversion

   fails.



   This function uses strptime with various string formats for parsing

   TIME_STRING.  This results in a parser that is not as lenient in

   interpreting TIME_STRING as I would like it to be.  Being based on

   strptime, it always allows shortened months, one-digit days, etc.,

   but due to the multitude of formats in which time can be

   represented, an ideal HTTP time parser would be even more

   forgiving.  It should completely ignore things like week days and

   concentrate only on the various forms of representing years,

   months, days, hours, minutes, and seconds.  For example, it would

   be nice if it accepted ISO 8601 out of the box.



   I've investigated free and PD code for this purpose, but none was

   usable.  getdate was big and unwieldy, and had potential copyright

   issues, or so I was informed.  Dr. Marcus Hennecke's atotm(),

   distributed with phttpd, is excellent, but we cannot use it because

   it is not assigned to the FSF.  So I stuck it with strptime.  */

time_t http_atotm(const char* time_string) {
  /* NOTE: Solaris strptime man page claims that %n and %t match white

     space, but that's not universally available.  Instead, we simply

     use ` ' to mean "skip all WS", which works under all strptime

     implementations I've tested.  */

  static const char* time_formats[] = {

      "%a, %d %b %Y %T", /* rfc1123: Thu, 29 Jan 1998 22:12:57 */

      "%A, %d-%b-%y %T", /* rfc850:  Thursday, 29-Jan-98 22:12:57 */

      "%a %b %d %T %Y", /* asctime: Thu Jan 29 22:12:57 1998 */

      "%a, %d-%b-%Y %T" /* cookies: Thu, 29-Jan-1998 22:12:57

                           (used in Set-Cookie, defined in the

                           Netscape cookie specification.) */

  };

  const char* oldlocale;

  char savedlocale[256];

  size_t i;

  time_t ret = (time_t)-1;

  /* Solaris strptime fails to recognize English month names in

     non-English locales, which we work around by temporarily setting

     locale to C before invoking strptime.  */

  oldlocale = setlocale(LC_TIME, NULL);

  if (oldlocale) {
    size_t l = strlen(oldlocale) + 1;

    if (l >= sizeof savedlocale)

      savedlocale[0] = '\0';

    else

      memcpy(savedlocale, oldlocale, l);
  }

  else

    savedlocale[0] = '\0';

  setlocale(LC_TIME, "C");

  for (i = 0; i < countof(time_formats); i++) {
    struct tm t;

    /* Some versions of strptime use the existing contents of struct

       tm to recalculate the date according to format.  Zero it out

       to prevent stack garbage from influencing strptime.  */

    xzero(t);

    if (check_end(strptime(time_string, time_formats[i], &t))) {
      ret = timegm(&t);

      break;
    }
  }

  /* Restore the previous locale. */

  if (savedlocale[0])

    setlocale(LC_TIME, savedlocale);

  return ret;
}

/* Appends the string represented by VALUE to FILENAME */

static void append_value_to_filename(char** filename, param_token const* const value, bool is_url_encoded) {
  int original_length = strlen(*filename);

  int new_length = strlen(*filename) + (value->e - value->b);

  *filename = xrealloc(*filename, new_length + 1);

  memcpy(*filename + original_length, value->b, (value->e - value->b));

  (*filename)[new_length] = '\0';

  if (is_url_encoded)

    url_unescape(*filename + original_length);
}

/* Parse the contents of the `Content-Disposition' header, extracting

   the information useful to Wget.  Content-Disposition is a header

   borrowed from MIME; when used in HTTP, it typically serves for

   specifying the desired file name of the resource.  For example:



       Content-Disposition: attachment; filename="flora.jpg"



   Wget will skip the tokens it doesn't care about, such as

   "attachment" in the previous example; it will also skip other

   unrecognized params.  If the header is syntactically correct and

   contains a file name, a copy of the file name is stored in

   *filename and true is returned.  Otherwise, the function returns

   false.



   The file name is stripped of directory components and must not be

   empty.



   Historically, this function returned filename prefixed with opt.dir_prefix,

   now that logic is handled by the caller, new code should pay attention,

   changed by crq, Sep 2010.



*/

bool parse_content_disposition(const char* hdr, char** filename) {
  param_token name, value;

  bool is_url_encoded = false;

  char* encodedFilename = NULL;

  char* unencodedFilename = NULL;

  for (; extract_param(&hdr, &name, &value, ';', &is_url_encoded); is_url_encoded = false) {
    int isFilename = BOUNDED_EQUAL_NO_CASE(name.b, name.e, "filename");

    if (isFilename && value.b != NULL) {
      /* Make the file name begin at the last slash or backslash. */

      bool isEncodedFilename;

      char** outFilename;

      const char* last_slash = memrchr(value.b, '/', value.e - value.b);

      const char* last_bs = memrchr(value.b, '\\', value.e - value.b);

      if (last_slash && last_bs)

        value.b = 1 + MAX(last_slash, last_bs);

      else if (last_slash || last_bs)

        value.b = 1 + (last_slash ? last_slash : last_bs);

      if (value.b == value.e)

        continue;

      /* Check if the name is "filename*" as specified in RFC 6266.

       * Since "filename" could be broken up as "filename*N" (RFC 2231),

       * a check is needed to make sure this is not the case */

      isEncodedFilename = *name.e == '*' && !c_isdigit(*(name.e + 1));

      outFilename = isEncodedFilename ? &encodedFilename : &unencodedFilename;

      if (*outFilename)

        append_value_to_filename(outFilename, &value, is_url_encoded);

      else {
        *outFilename = strdupdelim(value.b, value.e);

        if (is_url_encoded)

          url_unescape(*outFilename);
      }
    }
  }

  if (encodedFilename) {
    xfree(unencodedFilename);

    *filename = encodedFilename;
  }

  else {
    xfree(encodedFilename);

    *filename = unencodedFilename;
  }

  if (*filename)

    return true;

  else

    return false;
}
