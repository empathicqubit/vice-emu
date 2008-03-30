/*
 * c128memlimit.c -- Builds the C128 memory limit table.
 *
 * Written by
 *  Andreas Boose <viceteam@t-online.de>
 *
 * This file is part of VICE, the Versatile Commodore Emulator.
 * See README for copyright notice.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307  USA.
 *
 */

#include "vice.h"

#include "c128memlimit.h"


#define NUM_SEGMENTS 14
#define NUM_CONFIGS 256

static const int mstart[NUM_SEGMENTS] = {
    0x00, 0x02, 0x04, 0x10, 0x20, 0x40, 0x80, 0xa0,
    0xc0, 0xd0, 0xe0, 0xf0, 0xfc, 0xff };

static const int mend[NUM_SEGMENTS] = {
    0x01, 0x03, 0x0f, 0x1f, 0x3f, 0x7f, 0x9f, 0xbf,
    0xcf, 0xdf, 0xef, 0xfb, 0xfe, 0xff };

static const int limit_tab[NUM_SEGMENTS][NUM_CONFIGS] = {
    /* 0000-01ff */
    {     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1 },

    /* 0200-03ff */
    { 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd,
      0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd, 0x03fd },

    /* 0400-0fff */
    { 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd,
      0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd, 0x0ffd },

    /* 1000-1fff */
    { 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd,
      0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd, 0x1ffd },

    /* 2000-3fff */
    { 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd,
      0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd, 0x3ffd },

    /* 4000-7fff */
    { 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,

      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd,
      0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd, 0x7ffd,
      0xbffd, 0xbffd, 0x9ffd, 0x7ffd, 0xbffd, 0xbffd, 0x9ffd, 0x7ffd },

    /* 8000-9fff */
    { 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,

      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,

      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,

      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,

      0xbffd, 0xbffd, 0xbffd, 0x9ffd, 0xbffd, 0xbffd, 0xbffd, 0x9ffd,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd, 0x9ffd,     -1, 0xbffd, 0xbffd, 0x9ffd,     -1 },

    /* a000-bfff */
    { 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,

      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
      0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd, 0xbffd,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xbffd, 0xbffd,     -1,     -1, 0xbffd, 0xbffd,     -1,     -1 },

    /* c000-cfff */
    { 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd,
      0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd, 0xcffd },

    /* d000-dfff */
    {     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd,
      0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd,
      0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd, 0xdffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xdffd,     -1,     -1,     -1, 0xdffd,     -1,     -1,     -1 },

    /* e000-efff */
    { 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd,
      0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd, 0xeffd },

    /* f000-fbff */
    { 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd,
      0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd, 0xfbfd },

    /* fc00-feff */
    { 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd,
      0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd, 0xfefd },

    /* ff00-ffff */
    {     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
          -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,

      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd,
      0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd, 0xfffd } };


void mem_limit_init(int mem_read_limit_tab[NUM_CONFIGS][0x101])
{
    int i, j, k;

    for (i = 0; i < NUM_CONFIGS; i++) {
        for (j = 0; j < NUM_SEGMENTS; j++) {
            for (k = mstart[j]; k <= mend[j]; k++) {
                mem_read_limit_tab[i][k] = limit_tab[j][i];
            }
        }
        mem_read_limit_tab[i][0x100] = -1;
    }
}

