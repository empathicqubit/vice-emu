/*
 * fsimage-gcr.c
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
#include <string.h>

#include "diskconstants.h"
#include "diskimage.h"
#include "fsimage-gcr.h"
#include "fsimage.h"
#include "gcr.h"
#include "log.h"
#include "lib.h"
#include "types.h"
#include "util.h"


static log_t fsimage_gcr_log = LOG_ERR;
static const BYTE gcr_image_header_expected[] =
    { 0x47, 0x43, 0x52, 0x2D, 0x31, 0x35, 0x34, 0x31, 0x00 };

/*-----------------------------------------------------------------------*/
/* Intial GCR buffer setup.  */

int fsimage_read_gcr_image(disk_image_t *image)
{
    unsigned int half_track;
    WORD max_track_length;
    BYTE buf[MAX_GCR_TRACKS * 4], num_half_tracks;
    fsimage_t *fsimage;

    fsimage = image->media.fsimage;

    num_half_tracks = image->half_tracks;

    /* Do G64 image file sanity checks, current VICE implementation
     * does only support image file version 0
     */
    if (util_fpread(fsimage->fd, buf, 12, 0) < 0) {
        log_error(fsimage_gcr_log, "Could not read GCR disk image.");
        return -1;
    }
    if (memcmp(gcr_image_header_expected, buf, sizeof(gcr_image_header_expected)) != 0) {
        log_error(fsimage_gcr_log, "Unexpected GCR header found." );
        return -1;
    }

    num_half_tracks = buf[9];

    if (num_half_tracks > MAX_GCR_TRACKS) {
        log_error(fsimage_gcr_log, "Too many half tracks." );
        return -1;
    }

    max_track_length = util_le_buf_to_word(&buf[10]);

    if (max_track_length > NUM_MAX_MEM_BYTES_TRACK) {
        log_error(fsimage_gcr_log, "Too large max track length.");
        return -1;
    }

    if (fread(buf, num_half_tracks * 4, 1, fsimage->fd) < 1) {
        log_error(fsimage_gcr_log, "Could not read GCR disk image.");
        return -1;
    }

    for (half_track = 0; half_track < num_half_tracks; half_track++) {
        DWORD offset;
        BYTE *track_data;
        offset = util_le_buf_to_dword(&buf[half_track * 4]);

        if (image->gcr->track_data[half_track] == NULL) {
            image->gcr->track_data[half_track] = lib_calloc(1, NUM_MAX_MEM_BYTES_TRACK);
        }
        track_data = image->gcr->track_data[half_track];
        image->gcr->track_size[half_track] = 6250;

        if (offset != 0) {
            BYTE len[2];
            WORD track_len;

            if (util_fpread(fsimage->fd, len, 2, offset) < 0) {
                log_error(fsimage_gcr_log, "Could not read GCR disk image.");
                return -1;
            }

            track_len = util_le_buf_to_word(len);

            if (track_len > max_track_length) {
                log_error(fsimage_gcr_log, "Could not read GCR disk image.");
                return -1;
            }

            image->gcr->track_size[half_track] = track_len;

            if (fread(track_data, track_len, 1, fsimage->fd) < 1) {
                log_error(fsimage_gcr_log, "Could not read GCR disk image.");
                return -1;
            }
            /* The speed zone info is ignored */
        }
    }
    for (; half_track < MAX_GCR_TRACKS; half_track++) {
        if (image->gcr->track_data[half_track]) {
            lib_free(image->gcr->track_data[half_track]);
            image->gcr->track_data[half_track] = NULL;
        }
    }
    return 0;
}
/*-----------------------------------------------------------------------*/
/* Seek to half track */

static long fsimage_gcr_seek_half_track(fsimage_t *fsimage, unsigned int half_track,
        WORD *max_track_length, BYTE *num_half_tracks)
{
    BYTE buf[4];

    if (fsimage->fd == NULL) {
        log_error(fsimage_gcr_log, "Attempt to read without disk image.");
        return -1;
    }
    if (util_fpread(fsimage->fd, buf, 3, 9) < 0) {
        log_error(fsimage_gcr_log, "Could not read GCR disk image.");
        return -1;
    }

    *max_track_length = util_le_buf_to_word(&buf[1]);
    if (*max_track_length > NUM_MAX_MEM_BYTES_TRACK) {
        log_error(fsimage_gcr_log, "Too large max track length.");
        return -1;
    }

    *num_half_tracks = buf[0];
    if (*num_half_tracks > MAX_GCR_TRACKS) {
        log_error(fsimage_gcr_log, "Too many half tracks." );
        return -1;
    }

    if (util_fpread(fsimage->fd, buf, 4, 12 + (half_track - 2) * 4) < 0) {
        log_error(fsimage_gcr_log, "Could not read GCR disk image.");
        return -1;
    }
    return util_le_buf_to_dword(buf);
}

/*-----------------------------------------------------------------------*/
/* Read an entire GCR track from the disk image.  */

int fsimage_gcr_read_half_track(disk_image_t *image, unsigned int half_track,
                                BYTE *gcr_data, int *gcr_track_size)
{
    WORD track_len;
    BYTE buf[4];
    long offset;
    fsimage_t *fsimage;
    WORD max_track_length;
    BYTE num_half_tracks;

    fsimage = image->media.fsimage;

    offset = fsimage_gcr_seek_half_track(fsimage, half_track, &max_track_length, &num_half_tracks);
    if (offset < 0) {
        return -1;
    }

    memset(gcr_data, 0, max_track_length);

    if (offset != 0) {
        if (util_fpread(fsimage->fd, buf, 2, offset) < 0) {
            log_error(fsimage_gcr_log, "Could not read GCR disk image.");
            return -1;
        }

        track_len = util_le_buf_to_word(buf);

        if ((track_len < 1) || (track_len > max_track_length)) {
            log_error(fsimage_gcr_log,
                      "Track field length %u is not supported.",
                      track_len);
            return -1;
        }

        *gcr_track_size = track_len;

        if (fread(gcr_data, track_len, 1, fsimage->fd) < 1) {
            log_error(fsimage_gcr_log, "Could not read GCR disk image.");
            return -1;
        }
    } else {
        const int raw_track_size[4] = { 6250, 6666, 7142, 7692 };
        *gcr_track_size = raw_track_size[disk_image_speed_map_1541(half_track / 2 - 1)];

        memset(gcr_data, 0x55, *gcr_track_size);
    }
    return 0;
}

static int fsimage_gcr_read_track(disk_image_t *image, unsigned int track,
                           BYTE *gcr_data, int *gcr_track_size)
{
    return fsimage_gcr_read_half_track(image, track << 1, gcr_data, gcr_track_size);
}

/*-----------------------------------------------------------------------*/
/* Write an entire GCR track to the disk image.  */

int fsimage_gcr_write_half_track(disk_image_t *image, unsigned int half_track,
                                 int gcr_track_size, BYTE *gcr_track_start_ptr)
{
    int gap, extend = 0;
    WORD max_track_length;
    BYTE buf[4];
    long offset;
    fsimage_t *fsimage;
    BYTE num_half_tracks;

    fsimage = image->media.fsimage;

    offset = fsimage_gcr_seek_half_track(fsimage, half_track, &max_track_length, &num_half_tracks);
    if (offset < 0) {
        return -1;
    }
    if (image->read_only != 0) {
        log_error(fsimage_gcr_log,
                  "Attempt to write to read-only disk image.");
        return -1;
    }

    if (gcr_track_size > max_track_length) {
        log_error(fsimage_gcr_log,
                  "Track too long for image.");
        return -1;
    }

    if (offset == 0) {
        offset = fseek(fsimage->fd, 0, SEEK_END);
        if (offset == 0) {
            offset = ftell(fsimage->fd);
        }
        if (offset < 0) {
            log_error(fsimage_gcr_log, "Could not extend GCR disk image.");
            return -1;
        }
        extend = 1;
    }

    if (gcr_track_start_ptr != NULL) {
        util_word_to_le_buf(buf, gcr_track_size);

        if (util_fpwrite(fsimage->fd, buf, 2, offset) < 0) {
            log_error(fsimage_gcr_log, "Could not write GCR disk image.");
            return -1;
        }

        /* Clear gap between the end of the actual track and the start of
           the next track.  */
        gap = max_track_length - gcr_track_size;
        if (gap > 0) {
            memset(gcr_track_start_ptr + gcr_track_size, 0, gap);
        }

        if (fwrite(gcr_track_start_ptr, max_track_length, 1, fsimage->fd) < 1) {
            log_error(fsimage_gcr_log, "Could not write GCR disk image.");
            return -1;
        }

        if (extend) {
            util_dword_to_le_buf(buf, offset);
            if (util_fpwrite(fsimage->fd, buf, 4, 12 + (half_track - 2) * 4) < 0) {
                log_error(fsimage_gcr_log, "Could not write GCR disk image.");
                return -1;
            }

            util_dword_to_le_buf(buf, disk_image_speed_map_1541(half_track / 2 - 1));
            if (util_fpwrite(fsimage->fd, buf, 4, 12 + (half_track - 2 + num_half_tracks) * 4) < 0) {
                log_error(fsimage_gcr_log, "Could not write GCR disk image.");
                return -1;
            }
        }
    }

    /* Make sure the stream is visible to other readers.  */
    fflush(fsimage->fd);

    return 0;
}

static int fsimage_gcr_write_track(disk_image_t *image, unsigned int track,
                            int gcr_track_size, BYTE *gcr_track_start_ptr)
{
  return fsimage_gcr_write_half_track(image, track << 1, gcr_track_size, gcr_track_start_ptr);
}

/*-----------------------------------------------------------------------*/
/* Read a sector from the GCR disk image.  */

int fsimage_gcr_read_sector(disk_image_t *image, BYTE *buf,
                               unsigned int track, unsigned int sector)
{
    BYTE *gcr_data;
    BYTE *gcr_track_start_ptr;
    int gcr_track_size, gcr_current_track_size;

    if (track > image->tracks) {
        log_error(fsimage_gcr_log,
                  "Track %i out of bounds.  Cannot read GCR track.",
                  track);
        return -1;
    }

    gcr_data = (BYTE*) lib_malloc(NUM_MAX_MEM_BYTES_TRACK);

    if (image->gcr == NULL) {
        if (fsimage_gcr_read_track(image, track, gcr_data,
            &gcr_track_size) < 0) {
            log_error(fsimage_gcr_log,
                      "Cannot read track %i from GCR image.", track);
            lib_free(gcr_data);
            return -1;
        }
        gcr_track_start_ptr = gcr_data;
        gcr_current_track_size = gcr_track_size;
    } else {
        gcr_track_start_ptr = image->gcr->track_data[(track * 2) - 2];
        gcr_current_track_size = image->gcr->track_size[(track * 2) - 2];
    }
    if ((gcr_track_start_ptr == NULL) || gcr_read_sector(gcr_track_start_ptr,
        gcr_current_track_size, buf, track, sector) < 0) {
        log_error(fsimage_gcr_log,
                  "Cannot find track: %i sector: %i within GCR image.",
                  track, sector);
        lib_free(gcr_data);
        return -1;
    }

    lib_free(gcr_data);

    return 0;
}


/*-----------------------------------------------------------------------*/
/* Write a sector to the GCR disk image.  */

int fsimage_gcr_write_sector(disk_image_t *image, BYTE *buf,
                                unsigned int track, unsigned int sector)
{
    BYTE *gcr_data;
    BYTE *gcr_track_start_ptr;
    int gcr_track_size, gcr_current_track_size;

    if (track > image->tracks) {
        log_error(fsimage_gcr_log,
                  "Track %i out of bounds.  Cannot write GCR sector",
                  track);
        return -1;
    }

    gcr_data = (BYTE*) lib_malloc(NUM_MAX_MEM_BYTES_TRACK);

    if (image->gcr == NULL) {
        if (fsimage_gcr_read_track(image, track, gcr_data,
            &gcr_track_size) < 0) {
            log_error(fsimage_gcr_log,
                      "Cannot read track %i from GCR image.", track);
            lib_free(gcr_data);
            return -1;
        }
        gcr_track_start_ptr = gcr_data;
        gcr_current_track_size = gcr_track_size;
    } else {
        if (image->gcr->track_data[(track * 2) - 2] == NULL) {
            image->gcr->track_data[(track * 2) - 2] = lib_calloc(1, NUM_MAX_MEM_BYTES_TRACK);
        }
        gcr_track_start_ptr = image->gcr->track_data[(track * 2) - 2];
        gcr_current_track_size = image->gcr->track_size[(track * 2) - 2];
    }
    if (gcr_write_sector(gcr_track_start_ptr,
        gcr_current_track_size, buf, track, sector) < 0) {
        log_error(fsimage_gcr_log,
                  "Could not find track %i sector %i in disk image",
                  track, sector);
        lib_free(gcr_data);
        return -1;
    }
    if (fsimage_gcr_write_track(image, track, gcr_current_track_size,
        gcr_track_start_ptr) < 0) {
        log_error(fsimage_gcr_log,
                  "Failed writing track %i to disk image.", track);
        lib_free(gcr_data);
        return -1;
    }

    lib_free(gcr_data);

    return 0;
}

/*-----------------------------------------------------------------------*/

void fsimage_gcr_init(void)
{
    fsimage_gcr_log = log_open("Filesystem Image GCR");
}
