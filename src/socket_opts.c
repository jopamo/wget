/* Helper for computing socket tuning settings from wget options.
   Copyright (C) 2024 Free Software Foundation,
   Inc.

   This file is part of GNU Wget.

   GNU Wget is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   GNU Wget is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Wget.  If not, see <http://www.gnu.org/licenses/>.  */

#include "wget.h"

#include <limits.h>

#include "socket_opts.h"

static int clamp_to_int(wgint configured) {
  if (configured <= 0)
    return 0;
  if (configured > INT_MAX)
    return INT_MAX;
  return (int)configured;
}

int wget_socket_rcvbuf_value(const struct options* opt) {
  if (!opt)
    return 0;

  int override = clamp_to_int(opt->tcp_rcvbuf);
  if (override > 0)
    return override;

  if (opt->limit_rate > 0 && opt->limit_rate < 8192) {
    wgint limit = opt->limit_rate;
    if (limit < 512)
      limit = 512;
    if (limit > INT_MAX)
      limit = INT_MAX;
    return (int)limit;
  }

  return 0;
}

int wget_socket_sndbuf_value(const struct options* opt) {
  if (!opt)
    return 0;

  return clamp_to_int(opt->tcp_sndbuf);
}

bool wget_socket_use_nodelay(const struct options* opt) {
  return opt && opt->tcp_nodelay;
}
