/* Dedicated helpers for Metalink checksum verification.
 * src/metalink_checks.c
 */

#include "wget.h"

#ifdef HAVE_METALINK

#include "metalink_checks.h"
#include "metalink.h"
#include "threading.h"
#include "evloop.h"
#include "utils.h"
#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#include <errno.h>
#include <stdio.h>

struct metalink_checksum_job {
  const metalink_file_t* mfile;
  const char* destname;
  bool size_ok;
  bool hash_ok;
  bool done;
};

static void metalink_run_checksum(const metalink_file_t* mfile, const char* destname, bool* size_ok, bool* hash_ok) {
  FILE* local_file;
  metalink_checksum_t **mchksum_ptr, *mchksum;

  if (!size_ok || !hash_ok || !destname || !mfile)
    return;

  *size_ok = false;
  *hash_ok = false;

  local_file = fopen(destname, "rb");
  if (!local_file) {
    logprintf(LOG_NOTQUIET, _("Could not open downloaded file.\n"));
    return;
  }

  logprintf(LOG_VERBOSE, _("Computing size for %s\n"), quote(destname));

  if (!mfile->size) {
    *size_ok = true;
    logprintf(LOG_VERBOSE, _("File size not declared. Skipping check.\n"));
  }
  else {
    wgint local_file_size = file_size(destname);

    if (local_file_size == -1) {
      logprintf(LOG_NOTQUIET, _("Could not get downloaded file's size.\n"));
      fclose(local_file);
      return;
    }

    DEBUGP(("Declared size: %lld\n", mfile->size));
    DEBUGP(("Computed size: %lld\n", (long long)local_file_size));

    if (local_file_size != (wgint)mfile->size) {
      logprintf(LOG_NOTQUIET, _("Size mismatch for file %s.\n"), quote(destname));
      fclose(local_file);
      return;
    }

    *size_ok = true;
    logputs(LOG_VERBOSE, _("Size matches.\n"));
  }

  for (mchksum_ptr = mfile->checksums; *mchksum_ptr; mchksum_ptr++) {
    char md2[MD2_DIGEST_SIZE];
    char md2_txt[2 * MD2_DIGEST_SIZE + 1];

    char md4[MD4_DIGEST_SIZE];
    char md4_txt[2 * MD4_DIGEST_SIZE + 1];

    char md5[MD5_DIGEST_SIZE];
    char md5_txt[2 * MD5_DIGEST_SIZE + 1];

    char sha1[SHA1_DIGEST_SIZE];
    char sha1_txt[2 * SHA1_DIGEST_SIZE + 1];

    char sha224[SHA224_DIGEST_SIZE];
    char sha224_txt[2 * SHA224_DIGEST_SIZE + 1];

    char sha256[SHA256_DIGEST_SIZE];
    char sha256_txt[2 * SHA256_DIGEST_SIZE + 1];

    char sha384[SHA384_DIGEST_SIZE];
    char sha384_txt[2 * SHA384_DIGEST_SIZE + 1];

    char sha512[SHA512_DIGEST_SIZE];
    char sha512_txt[2 * SHA512_DIGEST_SIZE + 1];

    *hash_ok = false;
    mchksum = *mchksum_ptr;

    if (c_strcasecmp(mchksum->type, "md2") && c_strcasecmp(mchksum->type, "md4") && c_strcasecmp(mchksum->type, "md5") && c_strcasecmp(mchksum->type, "sha1") &&
        c_strcasecmp(mchksum->type, "sha-1") && c_strcasecmp(mchksum->type, "sha224") && c_strcasecmp(mchksum->type, "sha-224") && c_strcasecmp(mchksum->type, "sha256") &&
        c_strcasecmp(mchksum->type, "sha-256") && c_strcasecmp(mchksum->type, "sha384") && c_strcasecmp(mchksum->type, "sha-384") && c_strcasecmp(mchksum->type, "sha512") &&
        c_strcasecmp(mchksum->type, "sha-512")) {
      DEBUGP(("Ignoring unsupported checksum type %s.\n", quote(mchksum->type)));
      continue;
    }

    logprintf(LOG_VERBOSE, _("Computing checksum for %s\n"), quote(destname));

    DEBUGP(("Declared hash: %s\n", mchksum->hash));

    if (c_strcasecmp(mchksum->type, "md2") == 0) {
      md2_stream(local_file, md2);
      wg_hex_to_string(md2_txt, md2, MD2_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", md2_txt));
      if (!strcmp(md2_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "md4") == 0) {
      md4_stream(local_file, md4);
      wg_hex_to_string(md4_txt, md4, MD4_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", md4_txt));
      if (!strcmp(md4_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "md5") == 0) {
      md5_stream(local_file, md5);
      wg_hex_to_string(md5_txt, md5, MD5_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", md5_txt));
      if (!strcmp(md5_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "sha1") == 0 || c_strcasecmp(mchksum->type, "sha-1") == 0) {
      sha1_stream(local_file, sha1);
      wg_hex_to_string(sha1_txt, sha1, SHA1_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", sha1_txt));
      if (!strcmp(sha1_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "sha224") == 0 || c_strcasecmp(mchksum->type, "sha-224") == 0) {
      sha224_stream(local_file, sha224);
      wg_hex_to_string(sha224_txt, sha224, SHA224_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", sha224_txt));
      if (!strcmp(sha224_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "sha256") == 0 || c_strcasecmp(mchksum->type, "sha-256") == 0) {
      sha256_stream(local_file, sha256);
      wg_hex_to_string(sha256_txt, sha256, SHA256_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", sha256_txt));
      if (!strcmp(sha256_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "sha384") == 0 || c_strcasecmp(mchksum->type, "sha-384") == 0) {
      sha384_stream(local_file, sha384);
      wg_hex_to_string(sha384_txt, sha384, SHA384_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", sha384_txt));
      if (!strcmp(sha384_txt, mchksum->hash))
        *hash_ok = true;
    }
    else if (c_strcasecmp(mchksum->type, "sha512") == 0 || c_strcasecmp(mchksum->type, "sha-512") == 0) {
      sha512_stream(local_file, sha512);
      wg_hex_to_string(sha512_txt, sha512, SHA512_DIGEST_SIZE);
      DEBUGP(("Computed hash: %s\n", sha512_txt));
      if (!strcmp(sha512_txt, mchksum->hash))
        *hash_ok = true;
    }

    if (*hash_ok)
      logputs(LOG_VERBOSE, _("Checksum matches.\n"));
    else
      logprintf(LOG_NOTQUIET, _("Checksum mismatch for file %s.\n"), quote(destname));

    break;
  }

  fclose(local_file);
}

static void metalink_checksum_work(void* arg) {
  struct metalink_checksum_job* job = arg;
  metalink_run_checksum(job->mfile, job->destname, &job->size_ok, &job->hash_ok);
}

static void metalink_checksum_complete(void* arg) {
  struct metalink_checksum_job* job = arg;
  job->done = true;
}

void wget_metalink_verify_checksums(const metalink_file_t* mfile, const char* destname, bool* size_ok, bool* hash_ok) {
  if (!size_ok || !hash_ok)
    return;

  if (!wget_worker_pool_available()) {
    metalink_run_checksum(mfile, destname, size_ok, hash_ok);
    return;
  }

  struct metalink_checksum_job job = {
      .mfile = mfile,
      .destname = destname,
      .size_ok = false,
      .hash_ok = false,
      .done = false,
  };

  if (!wget_worker_pool_submit(metalink_checksum_work, metalink_checksum_complete, &job)) {
    metalink_run_checksum(mfile, destname, size_ok, hash_ok);
    return;
  }

  while (!job.done)
    wget_ev_loop_run_once();

  *size_ok = job.size_ok;
  *hash_ok = job.hash_ok;
}

#endif /* HAVE_METALINK */
