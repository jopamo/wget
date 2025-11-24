/* Tests for metalink checksum helpers. */

#include "wget.h"

#ifdef HAVE_METALINK

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <metalink/metalink_parser.h>

#include "metalink_checks.h"
#include "threading.h"
#include "evloop.h"

static char* write_temp_file(const char* contents) {
  char template[] = "/tmp/wget_metalink_XXXXXX";
  int fd = mkstemp(template);
  if (fd < 0)
    return NULL;
  size_t len = strlen(contents);
  if (write(fd, contents, len) != (ssize_t)len) {
    close(fd);
    unlink(template);
    return NULL;
  }
  close(fd);
  return xstrdup(template);
}

static void run_checksum(metalink_file_t* mfile, const char* path, bool expect_size, bool expect_hash, bool use_workers) {
  bool size_ok = false;
  bool hash_ok = false;

  if (use_workers) {
    wget_ev_loop_init();
    assert(wget_worker_pool_init(0));
  }

  wget_metalink_verify_checksums(mfile, path, &size_ok, &hash_ok);

  if (use_workers) {
    wget_worker_pool_shutdown();
    wget_ev_loop_deinit();
  }

  assert(size_ok == expect_size);
  assert(hash_ok == expect_hash);
}

int main(void) {
  const char* payload = "hello world";
  size_t payload_len = strlen(payload);
  char* temp_file = write_temp_file(payload);
  assert(temp_file != NULL);

  metalink_checksum_t checksum = {0};
  checksum.type = xstrdup("sha256");
  checksum.hash = xstrdup("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

  metalink_checksum_t* checksum_list[] = {&checksum, NULL};

  metalink_file_t mfile = {
      .name = xstrdup("payload"),
      .size = (wgint)payload_len,
      .checksums = checksum_list,
  };

  run_checksum(&mfile, temp_file, true, true, false);
  run_checksum(&mfile, temp_file, true, true, true);

  mfile.size = (wgint)(payload_len + 1);
  run_checksum(&mfile, temp_file, false, false, false);
  mfile.size = (wgint)payload_len;

  char* original_hash = checksum.hash;
  checksum.hash = (char*)"0000";
  run_checksum(&mfile, temp_file, true, false, false);
  checksum.hash = original_hash;

  unlink(temp_file);
  xfree(temp_file);
  xfree(mfile.name);
  xfree(checksum.type);
  xfree(checksum.hash);
  return 0;
}

#else
int main(void) {
  return 0;
}
#endif
