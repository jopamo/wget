/* Utility functions for writing WARC files
 * src/warc.c
 */

#include "wget.h"
#include "hash.h"
#include "utils.h"
#include "version.h"
#include "dirname.h"
#include "url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tmpdir.h>
#include <sha1.h>
#include <base32.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef HAVE_LIBUUID
#include <uuid/uuid.h>
#elif HAVE_UUID_CREATE
#include <uuid.h>
#endif

#include "warc.h"
#include "exits.h"

/* The log file (a temporary file that contains a copy
   of the wget log) */
static FILE* warc_log_fp;

/* The manifest file (a temporary file that contains the
   warcinfo uuid of every file in this crawl) */
static FILE* warc_manifest_fp;

/* The current WARC file (or NULL, if WARC is disabled) */
static FILE* warc_current_file;

#ifdef HAVE_LIBZ
/* The gzip stream for the current WARC file
   (or NULL, if WARC or gzip is disabled) */
static gzFile warc_current_gzfile;

/* The offset of the current gzip record in the WARC file */
static off_t warc_current_gzfile_offset;

/* The uncompressed size (so far) of the current record */
static off_t warc_current_gzfile_uncompressed_size;
#endif

/* This is true until a warc_write_* method fails */
static bool warc_write_ok;

/* The current CDX file (or NULL, if CDX is disabled) */
static FILE* warc_current_cdx_file;

/* The record id of the warcinfo record of the current WARC file */
static char warc_current_warcinfo_uuid_str[48];

/* The file name of the current WARC file */
static char* warc_current_filename;

/* The serial number of the current WARC file
   incremented each time a new file is opened and used in the filename */
static int warc_current_file_number;

/* The table of CDX records, if deduplication is enabled */
static struct hash_table* warc_cdx_dedup_table;

static bool warc_start_new_file(bool meta);

struct warc_cdx_record {
  char* url;
  char* uuid;
  char digest[SHA1_DIGEST_SIZE];
};

static unsigned long warc_hash_sha1_digest(const void* key) {
  /* Use the first bytes of the digest as hash input */
  unsigned long v = 0;
  memcpy(&v, key, sizeof(unsigned long));
  return v;
}

static int warc_cmp_sha1_digest(const void* digest1, const void* digest2) {
  return !memcmp(digest1, digest2, SHA1_DIGEST_SIZE);
}

/* Writes SIZE bytes from BUFFER to the current WARC file
   through gzwrite if compression is enabled
   Returns the number of uncompressed bytes written */
static size_t warc_write_buffer(const char* buffer, size_t size) {
#ifdef HAVE_LIBZ
  if (warc_current_gzfile) {
    warc_current_gzfile_uncompressed_size += size;
    return gzwrite(warc_current_gzfile, buffer, size);
  }
#endif
  return fwrite(buffer, 1, size, warc_current_file);
}

/* Writes STR to the current WARC file
   Returns false and sets warc_write_ok to false on error */
static bool warc_write_string(const char* str) {
  size_t n;

  if (!warc_write_ok)
    return false;

  n = strlen(str);
  if (n != warc_write_buffer(str, n))
    warc_write_ok = false;

  return warc_write_ok;
}

#define EXTRA_GZIP_HEADER_SIZE 14
#define GZIP_STATIC_HEADER_SIZE 10
#define FLG_FEXTRA 0x04
#define OFF_FLG 3

/* Starts a new WARC record and writes the version header
   If opt.warc_maxsize is set and the current file is becoming too large
   this opens a new WARC file

   If compression is enabled, this starts a new gzip stream in
   the current WARC file

   Returns false and sets warc_write_ok to false on error */
static bool warc_write_start_record(void) {
  if (!warc_write_ok)
    return false;

  fflush(warc_current_file);
  if (opt.warc_maxsize > 0 && ftello(warc_current_file) >= opt.warc_maxsize)
    warc_start_new_file(false);

#ifdef HAVE_LIBZ
  /* Start a gzip stream if requested */
  if (opt.warc_compression_enabled) {
    int dup_fd;

    /* Record the starting offset of the new record */
    warc_current_gzfile_offset = ftello(warc_current_file);

    /* Reserve space for the extra gzip header field
       warc_write_end_record will fill this with size metadata */
    if (fseeko(warc_current_file, EXTRA_GZIP_HEADER_SIZE, SEEK_CUR) < 0) {
      logprintf(LOG_NOTQUIET, _("Error setting WARC file position.\n"));
      warc_write_ok = false;
      return false;
    }

    if (fflush(warc_current_file) != 0) {
      logprintf(LOG_NOTQUIET, _("Error flushing WARC file to disk.\n"));
      warc_write_ok = false;
      return false;
    }

    dup_fd = dup(fileno(warc_current_file));
    if (dup_fd < 0) {
      logprintf(LOG_NOTQUIET, _("Error duplicating WARC file file descriptor.\n"));
      warc_write_ok = false;
      return false;
    }

    warc_current_gzfile = gzdopen(dup_fd, "wb9");
    warc_current_gzfile_uncompressed_size = 0;

    if (warc_current_gzfile == NULL) {
      logprintf(LOG_NOTQUIET, _("Error opening GZIP stream to WARC file.\n"));
      close(dup_fd);
      warc_write_ok = false;
      return false;
    }
  }
#endif

  warc_write_string("WARC/1.0\r\n");
  return warc_write_ok;
}

/* Writes a WARC header to the current record
   This must be called between warc_write_start_record and
   warc_write_block_from_file */
static bool warc_write_header(const char* name, const char* value) {
  if (value) {
    warc_write_string(name);
    warc_write_string(": ");
    warc_write_string(value);
    warc_write_string("\r\n");
  }
  return warc_write_ok;
}

/* Writes a WARC header whose value is a URI enclosed in angle brackets
   Must be called between warc_write_start_record and
   warc_write_block_from_file */
static bool warc_write_header_uri(const char* name, const char* value) {
  if (value) {
    warc_write_string(name);
    warc_write_string(": <");
    warc_write_string(value);
    warc_write_string(">\r\n");
  }
  return warc_write_ok;
}

/* Copies the contents of DATA_IN to the WARC record
   Adds a Content-Length header to the WARC record
   Call this after warc_write_header then call warc_write_end_record */
static bool warc_write_block_from_file(FILE* data_in) {
  char content_length[MAX_INT_TO_STRING_LEN(off_t)];
  char buffer[BUFSIZ];
  size_t s;

  if (fseeko(data_in, 0L, SEEK_END) != 0) {
    warc_write_ok = false;
    return false;
  }

  number_to_string(content_length, ftello(data_in));
  warc_write_header("Content-Length", content_length);

  /* End of the WARC header section */
  warc_write_string("\r\n");

  if (fseeko(data_in, 0L, SEEK_SET) != 0)
    warc_write_ok = false;

  while (warc_write_ok && (s = fread(buffer, 1, BUFSIZ, data_in)) > 0) {
    if (warc_write_buffer(buffer, s) < s)
      warc_write_ok = false;
  }

  return warc_write_ok;
}

/* Close the current WARC record

   If compression is enabled, this closes the current gzip stream and
   fills the extra gzip header with uncompressed and compressed lengths */
static bool warc_write_end_record(void) {
  if (!warc_write_ok)
    return warc_write_ok;

  if (warc_write_buffer("\r\n\r\n", 4) != 4) {
    warc_write_ok = false;
    return false;
  }

#ifdef HAVE_LIBZ
  /* We start a new gzip stream for each record */
  if (warc_write_ok && warc_current_gzfile) {
    char extra_header[EXTRA_GZIP_HEADER_SIZE];
    char static_header[GZIP_STATIC_HEADER_SIZE];
    off_t current_offset;
    off_t uncompressed_size;
    off_t compressed_size;
    size_t result;

    if (gzclose(warc_current_gzfile) != Z_OK) {
      warc_write_ok = false;
      return false;
    }

    warc_current_gzfile = NULL;

    fflush(warc_current_file);
    fseeko(warc_current_file, 0, SEEK_END);

    /* The WARC spec suggests adding skip length data in the extra header
       field of the gzip stream

       warc_write_start_record reserved space for the extra header at
       warc_current_gzfile_offset with size EXTRA_GZIP_HEADER_SIZE

       The static gzip header starts at
       warc_current_gzfile_offset + EXTRA_GZIP_HEADER_SIZE

       We must:
       1. Move the static gzip header to warc_current_gzfile_offset
       2. Set the FEXTRA flag in the gzip header
       3. Write our extra header payload after the static header */
    current_offset = ftello(warc_current_file);
    uncompressed_size = current_offset - warc_current_gzfile_offset;
    compressed_size = warc_current_gzfile_uncompressed_size;

    result = fseeko(warc_current_file, warc_current_gzfile_offset + EXTRA_GZIP_HEADER_SIZE, SEEK_SET);
    if (result != 0) {
      warc_write_ok = false;
      return false;
    }

    result = fread(static_header, 1, GZIP_STATIC_HEADER_SIZE, warc_current_file);
    if (result != GZIP_STATIC_HEADER_SIZE) {
      warc_write_ok = false;
      return false;
    }

    static_header[OFF_FLG] = static_header[OFF_FLG] | FLG_FEXTRA;

    fseeko(warc_current_file, warc_current_gzfile_offset, SEEK_SET);
    fwrite(static_header, 1, GZIP_STATIC_HEADER_SIZE, warc_current_file);

    /* XLEN, the length of the extra header fields */
    extra_header[0] = (EXTRA_GZIP_HEADER_SIZE - 2) & 255;
    extra_header[1] = ((EXTRA_GZIP_HEADER_SIZE - 2) >> 8) & 255;

    /* Extra header field identifier for the WARC skip length */
    extra_header[2] = 's';
    extra_header[3] = 'l';

    /* Size of the field value (8 bytes) */
    extra_header[4] = 8 & 255;
    extra_header[5] = (8 >> 8) & 255;

    /* Size of the uncompressed record */
    extra_header[6] = uncompressed_size & 255;
    extra_header[7] = (uncompressed_size >> 8) & 255;
    extra_header[8] = (uncompressed_size >> 16) & 255;
    extra_header[9] = (uncompressed_size >> 24) & 255;

    /* Size of the compressed record */
    extra_header[10] = compressed_size & 255;
    extra_header[11] = (compressed_size >> 8) & 255;
    extra_header[12] = (compressed_size >> 16) & 255;
    extra_header[13] = (compressed_size >> 24) & 255;

    fseeko(warc_current_file, warc_current_gzfile_offset + GZIP_STATIC_HEADER_SIZE, SEEK_SET);
    fwrite(extra_header, 1, EXTRA_GZIP_HEADER_SIZE, warc_current_file);

    fflush(warc_current_file);
    fseeko(warc_current_file, 0, SEEK_END);
  }
#endif /* HAVE_LIBZ */

  return warc_write_ok;
}

/* Writes the WARC-Date header for the given timestamp
   If timestamp is NULL, the current time is used */
static bool warc_write_date_header(const char* timestamp) {
  char current_timestamp[21];

  return warc_write_header("WARC-Date", timestamp ? timestamp : warc_timestamp(current_timestamp, sizeof(current_timestamp)));
}

/* Writes the WARC-IP-Address header for the given IP
   If IP is NULL, no header is written */
static bool warc_write_ip_header(const ip_address* ip) {
  if (ip != NULL)
    return warc_write_header("WARC-IP-Address", print_address(ip));

  return warc_write_ok;
}

/* warc_sha1_stream_with_payload is a modified sha1_stream which computes
   two digests in one pass

   Compute SHA1 digests for bytes read from STREAM

   The digest of the complete file is written into RES_BLOCK

   If payload_offset >= 0, a second digest is computed over the portion
   of the file starting at payload_offset, and that digest is written
   into RES_PAYLOAD */
static int warc_sha1_stream_with_payload(FILE* stream, void* res_block, void* res_payload, off_t payload_offset) {
#define BLOCKSIZE 32768

  struct sha1_ctx ctx_block;
  struct sha1_ctx ctx_payload;
  off_t pos = 0;
  off_t sum = 0;

  char* buffer = xmalloc(BLOCKSIZE + 72);

  sha1_init_ctx(&ctx_block);
  if (payload_offset >= 0)
    sha1_init_ctx(&ctx_payload);

  while (1) {
    off_t n;
    sum = 0;

    while (1) {
      n = fread(buffer + sum, 1, BLOCKSIZE - sum, stream);
      sum += n;
      pos += n;

      if (sum == BLOCKSIZE)
        break;

      if (n == 0) {
        if (ferror(stream)) {
          xfree(buffer);
          return 1;
        }
        goto process_partial_block;
      }

      if (feof(stream))
        goto process_partial_block;
    }

    sha1_process_bytes(buffer, BLOCKSIZE, &ctx_block);

    if (payload_offset >= 0 && payload_offset < pos) {
      off_t start_of_payload = payload_offset - (pos - BLOCKSIZE);
      if (start_of_payload <= 0)
        start_of_payload = 0;

      sha1_process_bytes(buffer + start_of_payload, BLOCKSIZE - start_of_payload, &ctx_payload);
    }
  }

process_partial_block:

  if (sum > 0) {
    sha1_process_bytes(buffer, sum, &ctx_block);
    if (payload_offset >= 0 && payload_offset < pos) {
      off_t start_of_payload = payload_offset - (pos - sum);
      if (start_of_payload <= 0)
        start_of_payload = 0;

      sha1_process_bytes(buffer + start_of_payload, sum - start_of_payload, &ctx_payload);
    }
  }

  sha1_finish_ctx(&ctx_block, res_block);
  if (payload_offset >= 0)
    sha1_finish_ctx(&ctx_payload, res_payload);

  xfree(buffer);
  return 0;

#undef BLOCKSIZE
}

/* Convert SHA1 digest to base32 encoded "sha1:DIGEST" in sha1_base32
   sha1_base32_size must be at least BASE32_LENGTH(SHA1_DIGEST_SIZE) + 6 */
static char* warc_base32_sha1_digest(const char* sha1_digest, char* sha1_base32, size_t sha1_base32_size) {
  if (sha1_base32_size >= BASE32_LENGTH(SHA1_DIGEST_SIZE) + 6) {
    memcpy(sha1_base32, "sha1:", 5);
    base32_encode(sha1_digest, SHA1_DIGEST_SIZE, sha1_base32 + 5, sha1_base32_size - 5);
  }
  else
    *sha1_base32 = 0;

  return sha1_base32;
}

/* Set block and payload digest headers for the record
   payload_offset < 0 disables payload digest */
static void warc_write_digest_headers(FILE* file, long payload_offset) {
  if (opt.warc_digests_enabled) {
    char sha1_res_block[SHA1_DIGEST_SIZE];
    char sha1_res_payload[SHA1_DIGEST_SIZE];

    rewind(file);
    if (warc_sha1_stream_with_payload(file, sha1_res_block, sha1_res_payload, payload_offset) == 0) {
      char digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 6];

      warc_write_header("WARC-Block-Digest", warc_base32_sha1_digest(sha1_res_block, digest, sizeof(digest)));

      if (payload_offset >= 0)
        warc_write_header("WARC-Payload-Digest", warc_base32_sha1_digest(sha1_res_payload, digest, sizeof(digest)));
    }
  }
}

/* Fill timestamp with current UTC time in WARC date format
   "YYYY-MM-DDTHH:MM:SSZ" plus terminating NUL */
char* warc_timestamp(char* timestamp, size_t timestamp_size) {
  time_t rawtime = time(NULL);
  struct tm* timeinfo = gmtime(&rawtime);

  if (strftime(timestamp, timestamp_size, "%Y-%m-%dT%H:%M:%SZ", timeinfo) == 0 && timestamp_size > 0)
    *timestamp = 0;

  return timestamp;
}

/* Fills urn_str with a UUID string in WARC-Record-Id format
   "<urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>" */
#if HAVE_LIBUUID
void warc_uuid_str(char* urn_str, size_t urn_size) {
  char uuid_str[37];
  uuid_t record_id;

  uuid_generate(record_id);
  uuid_unparse(record_id, uuid_str);

  snprintf(urn_str, urn_size, "<urn:uuid:%s>", uuid_str);
}
#elif HAVE_UUID_CREATE
void warc_uuid_str(char* urn_str, size_t urn_size) {
  char* uuid_str;
  uuid_t record_id;

  uuid_create(&record_id, NULL);
  uuid_to_string(&record_id, &uuid_str, NULL);

  snprintf(urn_str, urn_size, "<urn:uuid:%s>", uuid_str);
  xfree(uuid_str);
}
#else
/* Fallback UUIDv4 generator based on random numbers
   See RFC 4122, UUID version 4 */
void warc_uuid_str(char* urn_str, size_t urn_size) {
  unsigned char uuid_data[16];
  int i;

  for (i = 0; i < 16; i++)
    uuid_data[i] = random_number(255);

  uuid_data[6] = (uuid_data[6] & 0x0F) | 0x40;
  uuid_data[8] = (uuid_data[8] & 0x3F) | 0x80;

  snprintf(urn_str, urn_size, "<urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x>", uuid_data[0], uuid_data[1], uuid_data[2], uuid_data[3], uuid_data[4], uuid_data[5],
           uuid_data[6], uuid_data[7], uuid_data[8], uuid_data[9], uuid_data[10], uuid_data[11], uuid_data[12], uuid_data[13], uuid_data[14], uuid_data[15]);
}
#endif

/* Write a warcinfo record to the current file
   Updates warc_current_warcinfo_uuid_str */
static bool warc_write_warcinfo_record(const char* filename) {
  FILE* warc_tmp;
  char timestamp[22];
  char* filename_basename;

  warc_uuid_str(warc_current_warcinfo_uuid_str, sizeof(warc_current_warcinfo_uuid_str));

  warc_timestamp(timestamp, sizeof(timestamp));

  filename_basename = base_name(filename);

  warc_write_start_record();
  warc_write_header("WARC-Type", "warcinfo");
  warc_write_header("Content-Type", "application/warc-fields");
  warc_write_header("WARC-Date", timestamp);
  warc_write_header("WARC-Record-ID", warc_current_warcinfo_uuid_str);
  warc_write_header("WARC-Filename", filename_basename);

  xfree(filename_basename);

  warc_tmp = warc_tempfile();
  if (warc_tmp == NULL)
    return false;

  fprintf(warc_tmp, "software: Wget/%s (%s)\r\n", version_string, OS_TYPE);
  fprintf(warc_tmp, "format: WARC File Format 1.0\r\n");
  fprintf(warc_tmp, "conformsTo: http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1_latestdraft.pdf\r\n");
  fprintf(warc_tmp, "robots: %s\r\n", opt.use_robots ? "classic" : "off");
  fprintf(warc_tmp, "wget-arguments: %s\r\n", program_argstring);

  if (opt.warc_user_headers) {
    int i;
    for (i = 0; opt.warc_user_headers[i]; i++)
      fprintf(warc_tmp, "%s\r\n", opt.warc_user_headers[i]);
  }
  fprintf(warc_tmp, "\r\n");

  warc_write_digest_headers(warc_tmp, -1);
  warc_write_block_from_file(warc_tmp);
  warc_write_end_record();

  if (!warc_write_ok)
    logprintf(LOG_NOTQUIET, _("Error writing warcinfo record to WARC file.\n"));

  fclose(warc_tmp);
  return warc_write_ok;
}

/* Open a new WARC file
   If meta is true, suffix "-meta" is used in the filename

   Steps:
   1. Close current WARC file
   2. Increment warc_current_file_number
   3. Open a new WARC file
   4. Write initial warcinfo record

   Returns true on success, false otherwise */
static bool warc_start_new_file(bool meta) {
#ifdef HAVE_LIBZ
  const char* extension = opt.warc_compression_enabled ? "warc.gz" : "warc";
#else
  const char* extension = "warc";
#endif

  if (opt.warc_filename == NULL)
    return false;

  if (warc_current_file != NULL) {
    fclose(warc_current_file);
    warc_current_file = NULL;
  }

  *warc_current_warcinfo_uuid_str = 0;
  xfree(warc_current_filename);

  warc_current_file_number++;

  if (meta)
    warc_current_filename = aprintf("%s-meta.%s", opt.warc_filename, extension);
  else if (opt.warc_maxsize > 0)
    warc_current_filename = aprintf("%s-%05d.%s", opt.warc_filename, warc_current_file_number, extension);
  else
    warc_current_filename = aprintf("%s.%s", opt.warc_filename, extension);

  logprintf(LOG_VERBOSE, _("Opening WARC file %s.\n\n"), quote(warc_current_filename));

  warc_current_file = fopen(warc_current_filename, "wb+");
  if (warc_current_file == NULL) {
    logprintf(LOG_NOTQUIET, _("Error opening WARC file %s.\n"), quote(warc_current_filename));
    return false;
  }

  if (!warc_write_warcinfo_record(warc_current_filename))
    return false;

  if (warc_manifest_fp)
    fprintf(warc_manifest_fp, "%s\n", warc_current_warcinfo_uuid_str);

  return true;
}

/* Open the CDX file for output */
static bool warc_start_cdx_file(void) {
  char* cdx_filename = aprintf("%s.cdx", opt.warc_filename);
  warc_current_cdx_file = fopen(cdx_filename, "a+");
  xfree(cdx_filename);

  if (warc_current_cdx_file == NULL)
    return false;

  /* CDX header:
   *
   * a - original url
   * b - date
   * m - mime type
   * s - response code
   * k - new style checksum
   * r - redirect
   * M - meta tags
   * V - compressed arc file offset
   * g - file name
   * u - record-id
   */
  fprintf(warc_current_cdx_file, " CDX a b a m s k r M V g u\n");
  fflush(warc_current_cdx_file);

  return true;
}

#define CDX_FIELDSEP " \t\r\n"

/* Parse CDX header, extracting field indices for original url,
   checksum, and record id */
static bool warc_parse_cdx_header(char* lineptr, int* field_num_original_url, int* field_num_checksum, int* field_num_record_id) {
  char* token;
  char* save_ptr;

  *field_num_original_url = -1;
  *field_num_checksum = -1;
  *field_num_record_id = -1;

  token = strtok_r(lineptr, CDX_FIELDSEP, &save_ptr);

  if (token != NULL && strcmp(token, "CDX") == 0) {
    int field_num = 0;
    while (token != NULL) {
      token = strtok_r(NULL, CDX_FIELDSEP, &save_ptr);
      if (token != NULL) {
        switch (token[0]) {
          case 'a':
            *field_num_original_url = field_num;
            break;
          case 'k':
            *field_num_checksum = field_num;
            break;
          case 'u':
            *field_num_record_id = field_num;
            break;
        }
      }
      field_num++;
    }
  }

  return *field_num_original_url != -1 && *field_num_checksum != -1 && *field_num_record_id != -1;
}

/* Parse a CDX record and insert it into warc_cdx_dedup_table */
static void warc_process_cdx_line(char* lineptr, int field_num_original_url, int field_num_checksum, int field_num_record_id) {
  char* original_url = NULL;
  char* checksum = NULL;
  char* record_id = NULL;
  char* token;
  char* save_ptr;
  int field_num = 0;

  token = strtok_r(lineptr, CDX_FIELDSEP, &save_ptr);
  while (token != NULL) {
    char** val;

    if (field_num == field_num_original_url)
      val = &original_url;
    else if (field_num == field_num_checksum)
      val = &checksum;
    else if (field_num == field_num_record_id)
      val = &record_id;
    else
      val = NULL;

    if (val != NULL)
      *val = strdup(token);

    token = strtok_r(NULL, CDX_FIELDSEP, &save_ptr);
    field_num++;
  }

  if (original_url != NULL && checksum != NULL && record_id != NULL) {
    size_t checksum_l;
    char* checksum_v;

    base32_decode_alloc(checksum, strlen(checksum), &checksum_v, &checksum_l);
    xfree(checksum);

    if (checksum_v != NULL && checksum_l == SHA1_DIGEST_SIZE) {
      struct warc_cdx_record* rec;
      rec = xmalloc(sizeof(struct warc_cdx_record));
      rec->url = original_url;
      rec->uuid = record_id;
      memcpy(rec->digest, checksum_v, SHA1_DIGEST_SIZE);
      hash_table_put(warc_cdx_dedup_table, rec->digest, rec);
      xfree(checksum_v);
    }
    else {
      xfree(original_url);
      xfree(checksum_v);
      xfree(record_id);
    }
  }
  else {
    xfree(checksum);
    xfree(original_url);
    xfree(record_id);
  }
}

/* Load CDX file from opt.warc_cdx_dedup_filename and populate
   warc_cdx_dedup_table */
static bool warc_load_cdx_dedup_file(void) {
  FILE* f;
  char* lineptr = NULL;
  size_t n = 0;
  ssize_t line_length;
  int field_num_original_url = -1;
  int field_num_checksum = -1;
  int field_num_record_id = -1;

  f = fopen(opt.warc_cdx_dedup_filename, "r");
  if (f == NULL)
    return false;

  line_length = getline(&lineptr, &n, f);
  if (line_length != -1)
    warc_parse_cdx_header(lineptr, &field_num_original_url, &field_num_checksum, &field_num_record_id);

  if (field_num_original_url == -1 || field_num_checksum == -1 || field_num_record_id == -1) {
    if (field_num_original_url == -1)
      logprintf(LOG_NOTQUIET, _("CDX file does not list original urls. (Missing column 'a'.)\n"));
    if (field_num_checksum == -1)
      logprintf(LOG_NOTQUIET, _("CDX file does not list checksums. (Missing column 'k'.)\n"));
    if (field_num_record_id == -1)
      logprintf(LOG_NOTQUIET, _("CDX file does not list record ids. (Missing column 'u'.)\n"));
  }
  else {
    int nrecords;

    warc_cdx_dedup_table = hash_table_new(1000, warc_hash_sha1_digest, warc_cmp_sha1_digest);

    do {
      line_length = getline(&lineptr, &n, f);
      if (line_length != -1)
        warc_process_cdx_line(lineptr, field_num_original_url, field_num_checksum, field_num_record_id);
    } while (line_length != -1);

    nrecords = hash_table_count(warc_cdx_dedup_table);
    logprintf(LOG_VERBOSE, ngettext("Loaded %d record from CDX.\n\n", "Loaded %d records from CDX.\n\n", nrecords), nrecords);
  }

  xfree(lineptr);
  fclose(f);

  return true;
}
#undef CDX_FIELDSEP

/* Lookup a duplicate CDX record for url and payload digest
   Returns NULL if no match or if dedup table is disabled */
static struct warc_cdx_record* warc_find_duplicate_cdx_record(const char* url, char* sha1_digest_payload) {
  struct warc_cdx_record* rec_existing;

  if (warc_cdx_dedup_table == NULL)
    return NULL;

  rec_existing = hash_table_get(warc_cdx_dedup_table, sha1_digest_payload);

  if (rec_existing && strcmp(rec_existing->url, url) == 0)
    return rec_existing;

  return NULL;
}

/* Initialize the WARC writer if opt.warc_filename is set */
void warc_init(void) {
  warc_write_ok = true;

  if (opt.warc_filename != NULL) {
    if (opt.warc_cdx_dedup_filename != NULL) {
      if (!warc_load_cdx_dedup_file()) {
        logprintf(LOG_NOTQUIET, _("Could not read CDX file %s for deduplication.\n"), quote(opt.warc_cdx_dedup_filename));
        exit(WGET_EXIT_GENERIC_ERROR);
      }
    }

    warc_manifest_fp = warc_tempfile();
    if (warc_manifest_fp == NULL) {
      logprintf(LOG_NOTQUIET, _("Could not open temporary WARC manifest file.\n"));
      exit(WGET_EXIT_GENERIC_ERROR);
    }

    if (opt.warc_keep_log) {
      warc_log_fp = warc_tempfile();
      if (warc_log_fp == NULL) {
        logprintf(LOG_NOTQUIET, _("Could not open temporary WARC log file.\n"));
        exit(WGET_EXIT_GENERIC_ERROR);
      }
      log_set_warc_log_fp(warc_log_fp);
    }

    warc_current_file_number = -1;
    if (!warc_start_new_file(false)) {
      logprintf(LOG_NOTQUIET, _("Could not open WARC file.\n"));
      exit(WGET_EXIT_GENERIC_ERROR);
    }

    if (opt.warc_cdx_enabled) {
      if (!warc_start_cdx_file()) {
        logprintf(LOG_NOTQUIET, _("Could not open CDX file for output.\n"));
        exit(WGET_EXIT_GENERIC_ERROR);
      }
    }
  }
}

/* Write metadata (manifest, configuration, log file) to WARC */
static void warc_write_metadata(void) {
  char manifest_uuid[48];
  FILE* warc_tmp_fp;

  if (opt.warc_maxsize > 0)
    warc_start_new_file(true);

  warc_uuid_str(manifest_uuid, sizeof(manifest_uuid));

  fflush(warc_manifest_fp);
  warc_write_metadata_record(manifest_uuid, "metadata://gnu.org/software/wget/warc/MANIFEST.txt", NULL, NULL, NULL, "text/plain", warc_manifest_fp, -1);

  warc_tmp_fp = warc_tempfile();
  if (warc_tmp_fp == NULL) {
    logprintf(LOG_NOTQUIET, _("Could not open temporary WARC file.\n"));
    exit(WGET_EXIT_GENERIC_ERROR);
  }
  fflush(warc_tmp_fp);
  fprintf(warc_tmp_fp, "%s\n", program_argstring);

  warc_write_resource_record(NULL, "metadata://gnu.org/software/wget/warc/wget_arguments.txt", NULL, manifest_uuid, NULL, "text/plain", warc_tmp_fp, -1);

  if (warc_log_fp != NULL) {
    warc_write_resource_record(NULL, "metadata://gnu.org/software/wget/warc/wget.log", NULL, manifest_uuid, NULL, "text/plain", warc_log_fp, -1);

    warc_log_fp = NULL;
    log_set_warc_log_fp(NULL);
  }
}

/* Finalize WARC writing at program exit */
void warc_close(void) {
  if (warc_current_file != NULL) {
    warc_write_metadata();
    *warc_current_warcinfo_uuid_str = 0;
    fclose(warc_current_file);
    warc_current_file = NULL;
  }

  if (warc_current_cdx_file != NULL) {
    fclose(warc_current_cdx_file);
    warc_current_cdx_file = NULL;
  }

  if (warc_log_fp != NULL) {
    fclose(warc_log_fp);
    warc_log_fp = NULL;
    log_set_warc_log_fp(NULL);
  }

  xfree(warc_current_filename);
}

/* Create a temporary file for WARC output
   The file is created in opt.warc_tempdir and is unlinked immediately
   so it is removed automatically on close */
FILE* warc_tempfile(void) {
  char filename[100];
  int fd;

  if (path_search(filename, sizeof(filename), opt.warc_tempdir, "wget", true) == -1)
    return NULL;

  fd = mkstemp(filename);
  if (fd < 0)
    return NULL;

  if (unlink(filename) < 0) {
    close(fd);
    return NULL;
  }

  return fdopen(fd, "wb+");
}

/* Write a WARC request record
   body is closed by this function */
bool warc_write_request_record(const char* url, const char* timestamp_str, const char* record_uuid, const ip_address* ip, FILE* body, off_t payload_offset) {
  warc_write_start_record();
  warc_write_header("WARC-Type", "request");
  warc_write_header_uri("WARC-Target-URI", url);
  warc_write_header("Content-Type", "application/http;msgtype=request");
  warc_write_date_header(timestamp_str);
  warc_write_header("WARC-Record-ID", record_uuid);
  warc_write_ip_header(ip);
  warc_write_header("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_digest_headers(body, payload_offset);
  warc_write_block_from_file(body);
  warc_write_end_record();

  fclose(body);

  return warc_write_ok;
}

/* Write a CDX record corresponding to a response
   warc_filename is currently unused, kept for compatibility */
static bool warc_write_cdx_record(const char* url,
                                  const char* timestamp_str,
                                  const char* mime_type,
                                  int response_code,
                                  const char* payload_digest,
                                  const char* redirect_location,
                                  off_t offset,
                                  const char* warc_filename WGET_ATTR_UNUSED,
                                  const char* response_uuid) {
  char timestamp_str_cdx[15];
  char offset_string[MAX_INT_TO_STRING_LEN(off_t)];
  const char* checksum;
  char* tmp_location = NULL;

  memcpy(timestamp_str_cdx, timestamp_str, 4);
  memcpy(timestamp_str_cdx + 4, timestamp_str + 5, 2);
  memcpy(timestamp_str_cdx + 6, timestamp_str + 8, 2);
  memcpy(timestamp_str_cdx + 8, timestamp_str + 11, 2);
  memcpy(timestamp_str_cdx + 10, timestamp_str + 14, 2);
  memcpy(timestamp_str_cdx + 12, timestamp_str + 17, 2);
  timestamp_str_cdx[14] = '\0';

  if (payload_digest != NULL)
    checksum = payload_digest + 5;
  else
    checksum = "-";

  if (mime_type == NULL || strlen(mime_type) == 0)
    mime_type = "-";

  if (redirect_location == NULL || strlen(redirect_location) == 0)
    tmp_location = strdup("-");
  else
    tmp_location = url_escape(redirect_location);

  number_to_string(offset_string, offset);

  fprintf(warc_current_cdx_file, "%s %s %s %s %d %s %s - %s %s %s\n", url, timestamp_str_cdx, url, mime_type, response_code, checksum, tmp_location, offset_string, warc_current_filename,
          response_uuid);
  fflush(warc_current_cdx_file);
  free(tmp_location);

  return true;
}

/* Write a WARC revisit record when a duplicate payload is found
   body is closed by this function */
static bool warc_write_revisit_record(const char* url, const char* timestamp_str, const char* concurrent_to_uuid, const char* payload_digest, const char* refers_to, const ip_address* ip, FILE* body) {
  char revisit_uuid[48];
  char block_digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 6];
  char sha1_res_block[SHA1_DIGEST_SIZE];

  warc_uuid_str(revisit_uuid, sizeof(revisit_uuid));

  sha1_stream(body, sha1_res_block);
  warc_base32_sha1_digest(sha1_res_block, block_digest, sizeof(block_digest));

  warc_write_start_record();
  warc_write_header("WARC-Type", "revisit");
  warc_write_header("WARC-Record-ID", revisit_uuid);
  warc_write_header("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_header("WARC-Concurrent-To", concurrent_to_uuid);
  warc_write_header("WARC-Refers-To", refers_to);
  warc_write_header("WARC-Profile", "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest");
  warc_write_header("WARC-Truncated", "length");
  warc_write_header_uri("WARC-Target-URI", url);
  warc_write_date_header(timestamp_str);
  warc_write_ip_header(ip);
  warc_write_header("Content-Type", "application/http;msgtype=response");
  warc_write_header("WARC-Block-Digest", block_digest);
  warc_write_header("WARC-Payload-Digest", payload_digest);
  warc_write_block_from_file(body);
  warc_write_end_record();

  fclose(body);

  return warc_write_ok;
}

/* Write a WARC response record
   body is closed by this function */
bool warc_write_response_record(const char* url,
                                const char* timestamp_str,
                                const char* concurrent_to_uuid,
                                const ip_address* ip,
                                FILE* body,
                                off_t payload_offset,
                                const char* mime_type,
                                int response_code,
                                const char* redirect_location) {
  char block_digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 6];
  char payload_digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 6];
  char sha1_res_block[SHA1_DIGEST_SIZE];
  char sha1_res_payload[SHA1_DIGEST_SIZE];
  char response_uuid[48];
  off_t offset = 0;

  if (opt.warc_digests_enabled) {
    struct warc_cdx_record* rec_existing;

    rewind(body);
    if (warc_sha1_stream_with_payload(body, sha1_res_block, sha1_res_payload, payload_offset) == 0) {
      rec_existing = warc_find_duplicate_cdx_record(url, sha1_res_payload);
      if (rec_existing != NULL) {
        bool result;

        logprintf(LOG_VERBOSE, _("Found exact match in CDX file. Saving revisit record to WARC.\n"));

        if (payload_offset > 0) {
          if (ftruncate(fileno(body), payload_offset) == -1)
            return false;
        }

        warc_base32_sha1_digest(sha1_res_payload, payload_digest, sizeof(payload_digest));
        result = warc_write_revisit_record(url, timestamp_str, concurrent_to_uuid, payload_digest, rec_existing->uuid, ip, body);

        return result;
      }

      warc_base32_sha1_digest(sha1_res_block, block_digest, sizeof(block_digest));
      warc_base32_sha1_digest(sha1_res_payload, payload_digest, sizeof(payload_digest));
    }
  }

  warc_uuid_str(response_uuid, sizeof(response_uuid));

  fseeko(warc_current_file, 0L, SEEK_END);
  offset = ftello(warc_current_file);

  warc_write_start_record();
  warc_write_header("WARC-Type", "response");
  warc_write_header("WARC-Record-ID", response_uuid);
  warc_write_header("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_header("WARC-Concurrent-To", concurrent_to_uuid);
  warc_write_header_uri("WARC-Target-URI", url);
  warc_write_date_header(timestamp_str);
  warc_write_ip_header(ip);
  warc_write_header("WARC-Block-Digest", block_digest);
  warc_write_header("WARC-Payload-Digest", payload_digest);
  warc_write_header("Content-Type", "application/http;msgtype=response");
  warc_write_block_from_file(body);
  warc_write_end_record();

  fclose(body);

  if (warc_write_ok && opt.warc_cdx_enabled) {
    warc_write_cdx_record(url, timestamp_str, mime_type, response_code, payload_digest, redirect_location, offset, warc_current_filename, response_uuid);
  }

  return warc_write_ok;
}

/* Common helper to write a resource or metadata record
   record_type is "resource" or "metadata"
   body is closed by this function */
static bool warc_write_record(const char* record_type,
                              const char* resource_uuid,
                              const char* url,
                              const char* timestamp_str,
                              const char* concurrent_to_uuid,
                              const ip_address* ip,
                              const char* content_type,
                              FILE* body,
                              off_t payload_offset) {
  char uuid_buf[48];

  if (resource_uuid == NULL) {
    warc_uuid_str(uuid_buf, sizeof(uuid_buf));
    resource_uuid = uuid_buf;
  }

  if (content_type == NULL)
    content_type = "application/octet-stream";

  warc_write_start_record();
  warc_write_header("WARC-Type", record_type);
  warc_write_header("WARC-Record-ID", resource_uuid);
  warc_write_header("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_header("WARC-Concurrent-To", concurrent_to_uuid);
  warc_write_header_uri("WARC-Target-URI", url);
  warc_write_date_header(timestamp_str);
  warc_write_ip_header(ip);
  warc_write_digest_headers(body, payload_offset);
  warc_write_header("Content-Type", content_type);
  warc_write_block_from_file(body);
  warc_write_end_record();

  fclose(body);

  return warc_write_ok;
}

/* Write a WARC resource record
   body is closed by this function */
bool warc_write_resource_record(const char* resource_uuid,
                                const char* url,
                                const char* timestamp_str,
                                const char* concurrent_to_uuid,
                                const ip_address* ip,
                                const char* content_type,
                                FILE* body,
                                off_t payload_offset) {
  return warc_write_record("resource", resource_uuid, url, timestamp_str, concurrent_to_uuid, ip, content_type, body, payload_offset);
}

/* Write a WARC metadata record
   body is closed by this function */
bool warc_write_metadata_record(const char* record_uuid,
                                const char* url,
                                const char* timestamp_str,
                                const char* concurrent_to_uuid,
                                ip_address* ip,
                                const char* content_type,
                                FILE* body,
                                off_t payload_offset) {
  return warc_write_record("metadata", record_uuid, url, timestamp_str, concurrent_to_uuid, ip, content_type, body, payload_offset);
}
