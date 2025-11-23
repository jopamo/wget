/* Helper declarations for socket tuning options.
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

#ifndef SOCKET_OPTS_H
#define SOCKET_OPTS_H

#include <stdbool.h>

struct options;

int wget_socket_rcvbuf_value(const struct options* opt);
int wget_socket_sndbuf_value(const struct options* opt);
bool wget_socket_use_nodelay(const struct options* opt);

#endif /* SOCKET_OPTS_H */
