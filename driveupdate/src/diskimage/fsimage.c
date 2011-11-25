/*
 * fsimage.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "archdep.h"
#include "cbmdos.h"
#include "diskconstants.h"
#include "diskimage.h"
#include "fsimage-flat.h"
#include "fsimage-gcr.h"
#include "fsimage.h"
#include "lib.h"
#include "log.h"
#include "types.h"
#include "zfile.h"


static log_t fsimage_log = LOG_DEFAULT;


void fsimage_name_set(disk_image_t *image, char *name)
{
    fsimage_t *fsimage;

    fsimage = image->media.fsimage;

    fsimage->name = name;
}

char *fsimage_name_get(disk_image_t *image)
{
    fsimage_t *fsimage;

    fsimage = image->media.fsimage;

    return fsimage->name;
}

/*-----------------------------------------------------------------------*/

void fsimage_media_create(disk_image_t *image)
{
    fsimage_t *fsimage;

    fsimage = lib_calloc(1, sizeof(fsimage_t));

    image->media.fsimage = fsimage;
}

void fsimage_media_destroy(disk_image_t *image)
{
    fsimage_t *fsimage;

    fsimage = image->media.fsimage;

    lib_free(fsimage->name);

    lib_free(fsimage);
}

/*-----------------------------------------------------------------------*/
int fsimage_open(disk_image_t *image)
{
    fsimage_t *fsimage;

    fsimage = image->media.fsimage;

    if (image->read_only) {
        fsimage->fd = zfile_fopen(fsimage->name, MODE_READ);
    } else {
        fsimage->fd = zfile_fopen(fsimage->name, MODE_READ_WRITE);

        /* If we cannot open the image read/write, try to open it read only. */
        if (fsimage->fd == NULL) {
            fsimage->fd = zfile_fopen(fsimage->name, MODE_READ);
            image->read_only = 1;
        }
    }

    if (fsimage->fd == NULL) {
        log_error(fsimage_log, "Cannot open file `%s'.", fsimage->name);
        return -1;
    }

    if (fsimage_flat_open(image)
        || fsimage_gcr_open(image)) {

        log_verbose("%s disk image recognised: %s, %d tracks%s",
                image->type_name, fsimage->name, image->ltracks,
                image->read_only ? " (read only)." : ".");
        return 0;
    }

    zfile_fclose(fsimage->fd);
    log_message(fsimage_log, "Unknown disk image `%s'.", fsimage->name);
    return -1;
}

int fsimage_close(disk_image_t *image)
{
    fsimage_t *fsimage;

    fsimage = image->media.fsimage;

    if (fsimage->fd == NULL) {
        log_error(fsimage_log, "Cannot close file `%s'.",  fsimage->name);
        return -1;
    }

    switch (image->type) {
    case DISK_IMAGE_TYPE_D64:
    case DISK_IMAGE_TYPE_D67:
    case DISK_IMAGE_TYPE_X64:
    case DISK_IMAGE_TYPE_D71:
    case DISK_IMAGE_TYPE_D81:
    case DISK_IMAGE_TYPE_D80:
    case DISK_IMAGE_TYPE_D82:
    case DISK_IMAGE_TYPE_D1M:
    case DISK_IMAGE_TYPE_D2M:
    case DISK_IMAGE_TYPE_D4M:
        fsimage_flat_close(image);
        break;
    case DISK_IMAGE_TYPE_G64:
        fsimage_gcr_close(image);
        break;
    }

    zfile_fclose(fsimage->fd);

    return 0;
}

/*-----------------------------------------------------------------------*/
/* Reads a complete physical track in native form */

int fsimage_read_track(disk_image_t *image, unsigned int track,
                       unsigned int head, disk_track_t *raw)
{
    switch (image->type) {
    case DISK_IMAGE_TYPE_D64:
    case DISK_IMAGE_TYPE_D67:
    case DISK_IMAGE_TYPE_X64:
    case DISK_IMAGE_TYPE_D71:
    case DISK_IMAGE_TYPE_D81:
    case DISK_IMAGE_TYPE_D80:
    case DISK_IMAGE_TYPE_D82:
    case DISK_IMAGE_TYPE_D1M:
    case DISK_IMAGE_TYPE_D2M:
    case DISK_IMAGE_TYPE_D4M:
        return fsimage_flat_read_track(image, track, head, raw);
    case DISK_IMAGE_TYPE_G64:
        return fsimage_gcr_read_track(image, track, head, raw);
    }

    log_error(fsimage_log,
            "Unknown disk image type %i.  Cannot read track.",
            image->type);
    return -1;
}

/* Writes a complete physical track from native form to image file */
int fsimage_write_track(disk_image_t *image, unsigned int track,
                       unsigned int head, disk_track_t *raw)
{
    fsimage_t *fsimage = image->media.fsimage;

    if (fsimage->fd == NULL) {
        log_error(fsimage_log, "Attempt to write without disk image.");
        return -1;
    }

    if (image->read_only != 0) {
        log_error(fsimage_log, "Attempt to write to read-only disk image.");
        return -1;
    }

    switch (image->type) {
    case DISK_IMAGE_TYPE_D64:
    case DISK_IMAGE_TYPE_D67:
    case DISK_IMAGE_TYPE_X64:
    case DISK_IMAGE_TYPE_D71:
    case DISK_IMAGE_TYPE_D81:
    case DISK_IMAGE_TYPE_D80:
    case DISK_IMAGE_TYPE_D82:
    case DISK_IMAGE_TYPE_D1M:
    case DISK_IMAGE_TYPE_D2M:
    case DISK_IMAGE_TYPE_D4M:
        return fsimage_flat_write_track(image, track, head, raw);
    case DISK_IMAGE_TYPE_G64:
        return fsimage_gcr_write_track(image, track, head, raw);
    }

    log_error(fsimage_log,
              "Unknown disk image type %i.  Cannot write track.",
              image->type);
    return -1;
}

/* Reads a logical sector */
int fsimage_read_sector(disk_image_t *image, BYTE *buf, unsigned int track,
                        unsigned int sector)
{
    fsimage_t *fsimage = image->media.fsimage;

    if (fsimage->fd == NULL) {
        log_error(fsimage_log, "Attempt to read without disk image.");
        return CBMDOS_IPE_NOT_READY;
    }

    switch (image->type) {
      case DISK_IMAGE_TYPE_D64:
      case DISK_IMAGE_TYPE_D67:
      case DISK_IMAGE_TYPE_D71:
      case DISK_IMAGE_TYPE_D81:
      case DISK_IMAGE_TYPE_D80:
      case DISK_IMAGE_TYPE_D82:
      case DISK_IMAGE_TYPE_X64:
      case DISK_IMAGE_TYPE_D1M:
      case DISK_IMAGE_TYPE_D2M:
      case DISK_IMAGE_TYPE_D4M:
        return fsimage_flat_read_sector(image, buf, track, sector);
      case DISK_IMAGE_TYPE_G64:
        return fsimage_gcr_read_sector(image, buf, track, sector);
    }
    log_error(fsimage_log,
              "Unknown disk image type %i.  Cannot read sector.",
              image->type);
    return -1;
}

/* Writes a logical sector */
int fsimage_write_sector(disk_image_t *image, BYTE *buf, unsigned int track,
                         unsigned int sector)
{
    fsimage_t *fsimage = image->media.fsimage;

    if (fsimage->fd == NULL) {
        log_error(fsimage_log, "Attempt to write without disk image.");
        return CBMDOS_IPE_NOT_READY;
    }

    if (image->read_only != 0) {
        log_error(fsimage_log, "Attempt to write to read-only disk image.");
        return CBMDOS_IPE_WRITE_PROTECT_ON;
    }

    switch (image->type) {
      case DISK_IMAGE_TYPE_D64:
      case DISK_IMAGE_TYPE_D67:
      case DISK_IMAGE_TYPE_D71:
      case DISK_IMAGE_TYPE_D81:
      case DISK_IMAGE_TYPE_D80:
      case DISK_IMAGE_TYPE_D82:
      case DISK_IMAGE_TYPE_X64:
      case DISK_IMAGE_TYPE_D1M:
      case DISK_IMAGE_TYPE_D2M:
      case DISK_IMAGE_TYPE_D4M:
        return fsimage_flat_write_sector(image, buf, track, sector);
      case DISK_IMAGE_TYPE_G64:
        return fsimage_gcr_write_sector(image, buf, track, sector);
    }

    log_error(fsimage_log, "Unknown disk image.  Cannot write sector.");
    return -1;
}

int fsimage_create(const char *name, unsigned int type)
{
    int rc = -1;
    disk_image_t *image;
    fsimage_t *fsimage;

    image = disk_image_create();
    image->device = DISK_IMAGE_DEVICE_FS;
    fsimage_media_create(image);
    fsimage_name_set(image, lib_stralloc(name));

    fsimage = image->media.fsimage;
    fsimage->fd = fopen(name, MODE_WRITE);

    if (fsimage->fd == NULL) {
        log_error(fsimage_log, "Cannot create disk image `%s'.",
                  fsimage->name);
        fsimage_media_destroy(image);
        disk_image_destroy(image);
        return -1;
    }

    switch(type) {
      case DISK_IMAGE_TYPE_D64:
      case DISK_IMAGE_TYPE_X64:
      case DISK_IMAGE_TYPE_D67:
      case DISK_IMAGE_TYPE_D71:
      case DISK_IMAGE_TYPE_D81:
      case DISK_IMAGE_TYPE_D80:
      case DISK_IMAGE_TYPE_D82:
      case DISK_IMAGE_TYPE_D1M:
      case DISK_IMAGE_TYPE_D2M:
      case DISK_IMAGE_TYPE_D4M:
          rc = fsimage_flat_create(image, type);
          break;
      case DISK_IMAGE_TYPE_G64:
          rc = fsimage_gcr_create(image, type);
          break;
      default:
          log_error(fsimage_log,
                  "Wrong image type.  Cannot create disk image.");
          break;
    }
    fclose(fsimage->fd);
    fsimage_media_destroy(image);
    disk_image_destroy(image);
    return rc;
}

/*-----------------------------------------------------------------------*/

void fsimage_init(void)
{
    fsimage_log = log_open("Filesystem Image");
    fsimage_flat_init();
    fsimage_gcr_init();
}

