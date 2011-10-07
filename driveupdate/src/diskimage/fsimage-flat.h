/*
 * fsimage-flat.h
 *
 * Written by
 *  Kajtar Zsolt <soci@c64.rulez.org>
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

#ifndef VICE_FSIMAGE_FLAT_H
#define VICE_FSIMAGE_FLAT_H

#include "types.h"

struct disk_image_s;
struct disk_track_s;

extern void fsimage_flat_init(void);

extern int fsimage_flat_read_sector(struct disk_image_s *image, BYTE *buf,
                                   unsigned int track, unsigned int sector);
extern int fsimage_flat_write_sector(struct disk_image_s *image, BYTE *buf,
                                    unsigned int track, unsigned int sector);
extern int fsimage_flat_read_track(struct disk_image_s *image,
                                  unsigned int track, unsigned int head,
                                  struct disk_track_s *raw);
extern int fsimage_flat_write_track(struct disk_image_s *image,
                                   unsigned int track, unsigned int head,
                                   struct disk_track_s *raw);
extern int fsimage_flat_create(struct disk_image_s *image, unsigned int type);
#endif

