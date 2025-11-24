/* HTTP response body streaming helpers.
 * src/http_body.c
 */

#include "http_body.h"

#include "wget.h"

#include <string.h>

#include "connect.h"
#include "retr.h"
#include "warc.h"
#include "utils.h"

struct http_body_async_closure {
  struct http_stat* hs;
  http_body_done_cb done_cb;
  FILE* warc_tmp;
  int warc_payload_offset;
};

static void http_body_retr_done_cb(int status, wgint qtyread, wgint qtywritten, double elapsed, void* user_data) {
  struct http_body_async_closure* closure = user_data;
  struct http_stat* hs = closure->hs;
  http_body_done_cb done_cb = closure->done_cb;

  if (status >= 0) {
    if (closure->warc_tmp != NULL) {
      bool r = warc_write_response_record(hs->url, hs->warc_timestamp_str, hs->warc_request_uuid, hs->warc_ip, closure->warc_tmp, closure->warc_payload_offset, hs->type, hs->statcode, hs->newloc);
      if (!r)
        status = WARC_ERR; /* Indicate WARC error */
    }
  }

  if (closure->warc_tmp != NULL)
    fclose(closure->warc_tmp);
  xfree(closure);

  done_cb(hs, status, qtyread, qtywritten, elapsed);
}

void http_body_download(struct http_stat* hs, int sock, FILE* fp, wgint contlen, wgint contrange, bool chunked_transfer_encoding, http_body_done_cb done_cb) {
  int warc_payload_offset = 0;
  FILE* warc_tmp = NULL;
  int warcerr = 0;
  int flags = 0;
  struct http_body_async_closure* closure;

  if (!hs) {
    done_cb(hs, WARC_ERR, 0, 0, 0);
    return;
  }

  if (opt.warc_filename != NULL) {
    warc_tmp = warc_tempfile();
    if (warc_tmp == NULL)
      warcerr = WARC_TMP_FOPENERR;

    if (warcerr == 0) {
      int head_len = strlen(hs->head);
      int warc_tmp_written = fwrite(hs->head, 1, head_len, warc_tmp);
      if (warc_tmp_written != head_len)
        warcerr = WARC_TMP_FWRITEERR;
      warc_payload_offset = head_len;
    }

    if (warcerr != 0) {
      if (warc_tmp != NULL)
        fclose(warc_tmp);
      done_cb(hs, warcerr, 0, 0, 0);
      return;
    }
  }

  if (fp != NULL) {
    if (opt.save_headers && hs->restval == 0)
      fwrite(hs->head, 1, strlen(hs->head), fp);
  }

  if (contlen != -1)
    flags |= rb_read_exactly;
  if (fp != NULL && hs->restval > 0 && contrange == 0)
    flags |= rb_skip_startpos;
  if (chunked_transfer_encoding)
    flags |= rb_chunked_transfer_encoding;

  if (hs->remote_encoding == ENC_GZIP)
    flags |= rb_compressed_gzip;

  hs->len = hs->restval;
  hs->rd_size = 0;

  closure = xcalloc(1, sizeof(struct http_body_async_closure));
  closure->hs = hs;
  closure->done_cb = done_cb;
  closure->warc_tmp = warc_tmp;
  closure->warc_payload_offset = warc_payload_offset;

  if (retr_body_start_async(wget_ev_loop_get(), hs->local_file, sock, fp, contlen != -1 ? contlen : 0, hs->restval, &hs->rd_size, &hs->len, &hs->dltime, flags, warc_tmp, http_body_retr_done_cb,
                            closure) < 0) {
    if (warc_tmp != NULL)
      fclose(warc_tmp);
    xfree(closure);
    done_cb(hs, -1, 0, 0, 0);  // Indicate error starting async transfer
    return;
  }
}