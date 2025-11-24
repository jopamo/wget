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

int http_body_download(struct http_stat* hs,
                       int sock,
                       FILE* fp,
                       wgint contlen,
                       wgint contrange,
                       bool chunked_transfer_encoding,
                       char* url,
                       char* warc_timestamp_str,
                       char* warc_request_uuid,
                       ip_address* warc_ip,
                       char* type,
                       int statcode,
                       char* head) {
  int warc_payload_offset = 0;
  FILE* warc_tmp = NULL;
  int warcerr = 0;
  int flags = 0;

  if (!hs)
    return WARC_ERR;

  if (opt.warc_filename != NULL) {
    warc_tmp = warc_tempfile();
    if (warc_tmp == NULL)
      warcerr = WARC_TMP_FOPENERR;

    if (warcerr == 0) {
      int head_len = strlen(head);
      int warc_tmp_written = fwrite(head, 1, head_len, warc_tmp);
      if (warc_tmp_written != head_len)
        warcerr = WARC_TMP_FWRITEERR;
      warc_payload_offset = head_len;
    }

    if (warcerr != 0) {
      if (warc_tmp != NULL)
        fclose(warc_tmp);
      return warcerr;
    }
  }

  if (fp != NULL) {
    if (opt.save_headers && hs->restval == 0)
      fwrite(head, 1, strlen(head), fp);
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

  hs->res = fd_read_body(hs->local_file,
                         sock,
                         fp,
                         contlen != -1 ? contlen : 0,
                         hs->restval,
                         &hs->rd_size,
                         &hs->len,
                         &hs->dltime,
                         flags,
                         warc_tmp);
  if (hs->res >= 0) {
    if (warc_tmp != NULL) {
      bool r = warc_write_response_record(url, warc_timestamp_str, warc_request_uuid, warc_ip, warc_tmp, warc_payload_offset, type, statcode, hs->newloc);
      if (!r)
        return WARC_ERR;
    }

    return RETRFINISHED;
  }

  if (warc_tmp != NULL)
    fclose(warc_tmp);

  if (hs->res == -2)
    return FWRITEERR;
  else if (hs->res == -3)
    return WARC_TMP_FWRITEERR;
  else {
    xfree(hs->rderrmsg);
    hs->rderrmsg = xstrdup(fd_errstr(sock));
    return RETRFINISHED;
  }
}
