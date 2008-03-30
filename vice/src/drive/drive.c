/*
 * drive.c - Hardware-level disk drive emulation.
 *
 * Written by
 *  Andreas Boose <viceteam@t-online.de>
 *
 * Based on old code by
 *  Daniel Sladic <sladic@eecg.toronto.edu>
 *  Ettore Perazzoli <ettore@comm2000.it>
 *  Andr� Fachat <fachat@physik.tu-chemnitz.de>
 *  Teemu Rantanen <tvr@cs.hut.fi>
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

/* TODO:
        - more accurate emulation of disk rotation.
        - different speeds within one track.
        - check for byte ready *within* `BVC', `BVS' and `PHP'.
        - serial bus handling might be faster.  */

#include "vice.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include "attach.h"
#include "diskconstants.h"
#include "diskimage.h"
#include "drive-overflow.h"
#include "drive.h"
#include "drivecpu.h"
#include "driveimage.h"
#include "drivesync.h"
#include "driverom.h"
#include "drivetypes.h"
#include "gcr.h"
#include "iecdrive.h"
#include "lib.h"
#include "log.h"
#include "machine-drive.h"
#include "machine.h"
#include "maincpu.h"
#include "resources.h"
#include "rotation.h"
#include "serial.h"
#include "types.h"
#include "ui.h"


/* Drive specific variables.  */
drive_t drive[2];

drive_context_t drive0_context;
drive_context_t drive1_context;

drive_context_t *drive_context[DRIVE_NUM];

/* Generic drive logging goes here.  */
static log_t drive_log = LOG_ERR;

/* If nonzero, at least one vaild drive ROM has already been loaded.  */
int rom_loaded = 0;

/* ------------------------------------------------------------------------- */

static int drive_led_color[2];

static void drive_extend_disk_image(unsigned int dnr);

/* ------------------------------------------------------------------------- */

void drive_set_disk_memory(BYTE *id, unsigned int track, unsigned int sector,
                           struct drive_context_s *drv)
{
    drive_t *drive;

    drive = drv->drive;

    if (drive->type == DRIVE_TYPE_1541
        || drive->type == DRIVE_TYPE_1541II
        || drive->type == DRIVE_TYPE_1570
        || drive->type == DRIVE_TYPE_1571
        || drive->type == DRIVE_TYPE_1571CR) {
        drv->cpud->drive_ram[0x12] = id[0];
        drv->cpud->drive_ram[0x13] = id[1];
        drv->cpud->drive_ram[0x16] = id[0];
        drv->cpud->drive_ram[0x17] = id[1];
        drv->cpud->drive_ram[0x18] = track;
        drv->cpud->drive_ram[0x19] = sector;
        drv->cpud->drive_ram[0x22] = track;
    }
}

void drive_set_last_read(unsigned int track, unsigned int sector, BYTE *buffer,
                         struct drive_context_s *drv)
{
    drive_t *drive;

    drive = drv->drive;

    drive_gcr_data_writeback(drive);
    drive_set_half_track(track * 2, drive);

    if (drive->type == DRIVE_TYPE_1541
        || drive->type == DRIVE_TYPE_1541II
        || drive->type == DRIVE_TYPE_1570
        || drive->type == DRIVE_TYPE_1571
        || drive->type == DRIVE_TYPE_1571CR) {
        memcpy(&(drv->cpud->drive_ram[0x0400]), buffer, 256);
    }
}

/* ------------------------------------------------------------------------- */

/* Global clock counters.  */
CLOCK drive_clk[2];

/* Initialize the hardware-level drive emulation (should be called at least
   once before anything else).  Return 0 on success, -1 on error.  */
int drive_init(void)
{
    int i;
    unsigned int dnr;

    if (rom_loaded)
        return 0;

    drive_rom_init();
    drive_image_init();

    drive_log = log_open("Drive");

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        char *logname;

        logname = lib_msprintf("Drive %i", dnr + 8);
        drive[dnr].log = log_open(logname);
        lib_free(logname);

        drive_clk[dnr] = 0L;
        drive[dnr].clk = &drive_clk[dnr];
        drive[dnr].mynumber = dnr;
    }

    if (drive_rom_load_images() < 0) {
        resources_set_value("Drive8Type", (resource_value_t)DRIVE_TYPE_NONE);
        resources_set_value("Drive9Type", (resource_value_t)DRIVE_TYPE_NONE);
        return -1;
    }

    log_message(drive_log, "Finished loading ROM images.");
    rom_loaded = 1;

    drive_overflow_init();

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        drive[dnr].drive_ram_expand2 = NULL;
        drive[dnr].drive_ram_expand4 = NULL;
        drive[dnr].drive_ram_expand6 = NULL;
        drive[dnr].drive_ram_expand8 = NULL;
        drive[dnr].drive_ram_expanda = NULL;

        machine_drive_port_default(drive_context[dnr]);
    }

    if (drive_check_type(drive[0].type, 0) < 1)
        resources_set_value("Drive8Type", (resource_value_t)DRIVE_TYPE_NONE);
    if (drive_check_type(drive[1].type, 1) < 1)
        resources_set_value("Drive9Type", (resource_value_t)DRIVE_TYPE_NONE);

    machine_drive_rom_setup_image(0);
    machine_drive_rom_setup_image(1);

    for (i = 0; i < 2; i++) {
        drive[i].gcr = gcr_create_image();
        drive[i].byte_ready_level = 1;
        drive[i].byte_ready_edge = 1;
        drive[i].GCR_dirty_track = 0;
        drive[i].GCR_write_value = 0x55;
        drive[i].GCR_track_start_ptr = drive[i].gcr->data;
        drive[i].GCR_current_track_size = 0;
        drive[i].attach_clk = (CLOCK)0;
        drive[i].detach_clk = (CLOCK)0;
        drive[i].attach_detach_clk = (CLOCK)0;
        drive[i].have_new_disk = 0;
        drive[i].old_led_status = 0;
        drive[i].old_half_track = 0;
        drive[i].side = 0;
        drive[i].GCR_image_loaded = 0;
        drive[i].read_only = 0;
        drive[i].clock_frequency = 1;

        rotation_reset(&drive[i]);
        drive_image_init_track_size_d64(&drive[i]);

        /* Position the R/W head on the directory track.  */
        drive_set_half_track(36, &drive[i]);
        drive_led_color[i] = DRIVE_ACTIVE_RED;
    }

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        drive_rom_initialize_traps(&drive[dnr]);

        drive_sync_clock_frequency(drive[dnr].type, &drive[dnr]);

        rotation_init((drive[dnr].clock_frequency == 2) ? 1 : 0, dnr);

        drive_cpu_init(drive_context[dnr], drive[dnr].type);

        /* Make sure the sync factor is acknowledged correctly.  */
        drive_sync_factor(drive_context[dnr]);

        /* Make sure the traps are moved as needed.  */
        if (drive[dnr].enable)
            drive_enable(drive_context[dnr]);
    }

    return 0;
}

void drive_shutdown(void)
{
    unsigned int dnr;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        drive_cpu_shutdown(drive_context[dnr]);
        gcr_destroy_image(drive[dnr].gcr);
    }
}

void drive_set_active_led_color(unsigned int type, unsigned int dnr)
{
    switch (type) {
      case DRIVE_TYPE_1541:
      case DRIVE_TYPE_1551:
      case DRIVE_TYPE_1570:
      case DRIVE_TYPE_1571:
      case DRIVE_TYPE_1571CR:
        drive_led_color[dnr] = DRIVE_ACTIVE_RED;
        break;
      case DRIVE_TYPE_1541II:
      case DRIVE_TYPE_1581:
        drive_led_color[dnr] = DRIVE_ACTIVE_GREEN;
        break;
      case DRIVE_TYPE_2031:
      case DRIVE_TYPE_2040:
      case DRIVE_TYPE_3040:
      case DRIVE_TYPE_4040:
      case DRIVE_TYPE_1001:
      case DRIVE_TYPE_8050:
      case DRIVE_TYPE_8250:
        drive_led_color[dnr] = DRIVE_ACTIVE_RED;
        break;
      default:
        drive_led_color[dnr] = DRIVE_ACTIVE_RED;
    }
}

int drive_set_disk_drive_type(unsigned int type, struct drive_context_s *drv)
{
    unsigned int dnr;

    dnr = drv->mynumber;

    if (machine_drive_rom_check_loaded(type) < 0)
        return -1;

    if (drive[dnr].byte_ready_active == 0x06)
        rotation_rotate_disk(&drive[dnr]);

    drive_sync_clock_frequency(type, &drive[dnr]);

    rotation_init(0, dnr);
    drive[dnr].type = type;
    drive[dnr].side = 0;
    machine_drive_rom_setup_image(dnr);
    drive_sync_factor(drv);
    drive_set_active_led_color(type, dnr);

    drive_cpu_init(drv, type);

    return 0;
}


/* Activate full drive emulation. */
int drive_enable(drive_context_t *drv)
{
    int i, drive_true_emulation = 0;
    unsigned int dnr;

    dnr = drv->mynumber;

    /* This must come first, because this might be called before the drive
       initialization.  */
    if (!rom_loaded)
        return -1;

    resources_get_value("DriveTrueEmulation", (void *)&drive_true_emulation);

    /* Always disable kernal traps. */
    if (drive_true_emulation)
        serial_set_truedrive(1);
    else
        return 0;

    if (drive[dnr].type == DRIVE_TYPE_NONE)
        return 0;

    /* Recalculate drive geometry.  */
    if (drive[dnr].image != NULL)
        drive_image_attach(drive[dnr].image, dnr + 8);

    drive_cpu_wake_up(drv);

    /* Make sure the UI is updated.  */
    for (i = 0; i < 2; i++) {
        if (drive[i].enable) {
            drive[i].old_led_status = -1;
            drive[i].old_half_track = -1;
        }
    }

    drive_set_active_led_color(drive[dnr].type, dnr);
    ui_enable_drive_status((drive[0].enable ? UI_DRIVE_ENABLE_0 : 0)
                           | ((drive[1].enable
                           || (drive[0].enable && DRIVE_IS_DUAL(drive[0].type))
                           ) ? UI_DRIVE_ENABLE_1 : 0),
                           drive_led_color);

    return 0;
}

/* Disable full drive emulation.  */
void drive_disable(drive_context_t *drv)
{
    int i, drive_true_emulation = 0;
    unsigned int dnr;

    dnr = drv->mynumber;

    /* This must come first, because this might be called before the true
       drive initialization.  */
    drive[dnr].enable = 0;
    iec_calculate_callback_index();

    resources_get_value("DriveTrueEmulation", (void *)&drive_true_emulation);

    if (rom_loaded && !drive_true_emulation)
        serial_set_truedrive(0);

    if (rom_loaded) {
        drive_cpu_sleep(drv);
        machine_drive_port_default(drv);

        drive_gcr_data_writeback(drv->drive);
    }

    /* Make sure the UI is updated.  */
    for (i = 0; i < 2; i++) {
        if (drive[i].enable) {
            drive[i].old_led_status = -1;
            drive[i].old_half_track = -1;
        }
    }

    ui_enable_drive_status((drive[0].enable ? UI_DRIVE_ENABLE_0 : 0)
                           | ((drive[1].enable
                           || (drive[0].enable && DRIVE_IS_DUAL(drive[0].type))
                           ) ? UI_DRIVE_ENABLE_1 : 0),
                           drive_led_color);
/*
    ui_enable_drive_status((drive[0].enable ? UI_DRIVE_ENABLE_0 : 0)
                           | (drive[1].enable ? UI_DRIVE_ENABLE_1 : 0),
                           drive_led_color);
*/
}

void drive_reset(void)
{
    unsigned int dnr;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++)
        drive_cpu_reset(drive_context[dnr]);
}

/*-------------------------------------------------------------------------- */

/* The following functions are time critical.  */

/* Move the head to half track `num'.  */
void drive_set_half_track(int num, drive_t *dptr)
{
    if ((dptr->type == DRIVE_TYPE_1541 || dptr->type == DRIVE_TYPE_1541II
        || dptr->type == DRIVE_TYPE_1551 || dptr->type == DRIVE_TYPE_1570
        || dptr->type == DRIVE_TYPE_2031) && num > 84)
        num = 84;
    if ((dptr->type == DRIVE_TYPE_1571 || dptr->type == DRIVE_TYPE_1571CR)
        && num > 140)
        num = 140;
    if (num < 2)
        num = 2;

    dptr->current_half_track = num;
    dptr->GCR_track_start_ptr = (dptr->gcr->data
                                + ((dptr->current_half_track / 2 - 1)
                                * NUM_MAX_BYTES_TRACK));

    if (dptr->GCR_current_track_size != 0)
#if 0
        dptr->GCR_head_offset
            *= (dptr->gcr->track_size[dptr->current_half_track
            / 2 - 1]) / dptr->GCR_current_track_size;
#else
        dptr->GCR_head_offset = (dptr->GCR_head_offset
            * dptr->gcr->track_size[dptr->current_half_track / 2 - 1])
            / dptr->GCR_current_track_size;
#endif
    else
        dptr->GCR_head_offset = 0;

    dptr->GCR_current_track_size =
        dptr->gcr->track_size[dptr->current_half_track / 2 - 1];
}

/* Return the write protect sense status. */
inline BYTE drive_write_protect_sense(drive_t *dptr)
{
    /* Set the write protection bit for the time the disk is pulled out on
       detach.  */
    if (dptr->detach_clk != (CLOCK)0) {
        if (*(dptr->clk) - dptr->detach_clk < DRIVE_DETACH_DELAY)
            return 0x10;
        dptr->detach_clk = (CLOCK)0;
    }
    /* Clear the write protection bit for the minimum time until a new disk
       can be inserted.  */
    if (dptr->attach_detach_clk != (CLOCK)0) {
        if (*(dptr->clk) - dptr->attach_detach_clk
            < DRIVE_ATTACH_DETACH_DELAY)
            return 0x0;
        dptr->attach_detach_clk = (CLOCK)0;
    }
    /* Set the write protection bit for the time the disk is put in on
       attach.  */
    if (dptr->attach_clk != (CLOCK)0) {
        if (*(dptr->clk) - dptr->attach_clk < DRIVE_ATTACH_DELAY)
            return 0x10;
        dptr->attach_clk = (CLOCK)0;
    }

    if (dptr->GCR_image_loaded == 0) {
        /* No disk in drive, write protection is on. */
        return 0x0;
    } else if (dptr->have_new_disk) {
        /* Disk has changed, make sure the drive sees at least one change in
           the write protect status. */
        dptr->have_new_disk = 0;
        return dptr->read_only ? 0x10 : 0x0;
    } else {
        return dptr->read_only ? 0x0 : 0x10;
    }
}

/* End of time critical functions.  */
/*-------------------------------------------------------------------------- */

/* Increment the head position by `step' half-tracks. Valid values
   for `step' are `+1' and `-1'.  */
void drive_move_head(int step, unsigned int dnr)
{
    drive_gcr_data_writeback(&drive[dnr]);
    if (drive[dnr].type == DRIVE_TYPE_1571
        || drive[dnr].type == DRIVE_TYPE_1571CR) {
        if (drive[dnr].current_half_track + step == 71)
            return;
    }
    drive_set_half_track(drive[dnr].current_half_track + step, &drive[dnr]);
}

/* Hack... otherwise you get internal compiler errors when optimizing on
    gcc2.7.2 on RISC OS */
static void gcr_data_writeback2(BYTE *buffer, BYTE *offset, unsigned int dnr,
                                unsigned int track, unsigned int sector)
{
    int rc;

    gcr_convert_GCR_to_sector(buffer, offset,
                              drive[dnr].GCR_track_start_ptr,
                              drive[dnr].GCR_current_track_size);
    if (buffer[0] != 0x7) {
        log_error(drive[dnr].log,
                  "Could not find data block id of T:%d S:%d.",
                  track, sector);
    } else {
        rc = disk_image_write_sector(drive[dnr].image, buffer + 1, track,
                                     sector);
        if (rc < 0)
            log_error(drive[dnr].log,
                      "Could not update T:%d S:%d.", track, sector);
    }
}

void drive_gcr_data_writeback(drive_t *drive)
{
    int extend;
    unsigned int track, sector, max_sector = 0;
    BYTE buffer[260], *offset;

    if (drive->image == NULL)
        return;

    track = drive->current_half_track / 2;

    if (!(drive->GCR_dirty_track))
        return;

    if (drive->image->type == DISK_IMAGE_TYPE_G64) {
        BYTE *gcr_track_start_ptr;
        unsigned int gcr_current_track_size;

        gcr_current_track_size = drive->gcr->track_size[track - 1];

        gcr_track_start_ptr = drive->gcr->data
                              + ((track - 1) * NUM_MAX_BYTES_TRACK);

        disk_image_write_track(drive->image, track,
                               gcr_current_track_size,
                               drive->gcr->speed_zone,
                               gcr_track_start_ptr);
        drive->GCR_dirty_track = 0;
        return;
    }

    if (drive->image->type == DISK_IMAGE_TYPE_D64
        || drive->image->type == DISK_IMAGE_TYPE_X64) {
        if (track > EXT_TRACKS_1541)
            return;
        max_sector = disk_image_sector_per_track(DISK_IMAGE_TYPE_D64, track);
        if (track > drive->image->tracks) {
            switch (drive->extend_image_policy) {
              case DRIVE_EXTEND_NEVER:
                drive->ask_extend_disk_image = 1;
                return;
              case DRIVE_EXTEND_ASK:
                if (drive->ask_extend_disk_image == 1) {
                    extend = ui_extend_image_dialog();
                    if (extend == 0) {
                        drive->ask_extend_disk_image = 0;
                        return;
                    } else {
                        drive_extend_disk_image(drive->mynumber);
                    }
                } else {
                    return;
                }
                break;
              case DRIVE_EXTEND_ACCESS:
                drive->ask_extend_disk_image = 1;
                drive_extend_disk_image(drive->mynumber);
                break;
            }
        }
    }

    if (drive->image->type == DISK_IMAGE_TYPE_D71) {
        if (track > MAX_TRACKS_1571)
            return;
        max_sector = disk_image_sector_per_track(DISK_IMAGE_TYPE_D71, track);
    }

    drive->GCR_dirty_track = 0;

    for (sector = 0; sector < max_sector; sector++) {

        offset = gcr_find_sector_header(track, sector,
                                        drive->GCR_track_start_ptr,
                                        drive->GCR_current_track_size);
        if (offset == NULL) {
            log_error(drive->log,
                      "Could not find header of T:%d S:%d.",
                      track, sector);
        } else {
            offset = gcr_find_sector_data(offset,
                                          drive->GCR_track_start_ptr,
                                          drive->GCR_current_track_size);
            if (offset == NULL) {
                log_error(drive->log,
                          "Could not find data sync of T:%d S:%d.",
                          track, sector);
            } else {
                gcr_data_writeback2(buffer, offset, drive->mynumber, track,
                                    sector);
            }
        }
    }
}

static void drive_extend_disk_image(unsigned int dnr)
{
    int rc;
    unsigned int track, sector;
    BYTE buffer[256];

    drive[dnr].image->tracks = EXT_TRACKS_1541;
    memset(buffer, 0, 256);
    for (track = NUM_TRACKS_1541 + 1; track <= EXT_TRACKS_1541; track++) {
        for (sector = 0;
             sector < disk_image_sector_per_track(DISK_IMAGE_TYPE_D64, track);
             sector++) {
             rc = disk_image_write_sector(drive[dnr].image, buffer, track,
                                          sector);
             if (rc < 0)
                 log_error(drive[dnr].log,
                           "Could not update T:%d S:%d.", track, sector);
        }
    }
}

int drive_match_bus(unsigned int drive_type, unsigned int drv, int bus_map)
{
    if ( (drive_type == DRIVE_TYPE_NONE)
      || (DRIVE_IS_IEEE(drive_type) && (bus_map & IEC_BUS_IEEE))
      || ((!DRIVE_IS_IEEE(drive_type)) && (bus_map & IEC_BUS_IEC))
    ) {
        return 1;
    }
    return 0;
}

int drive_check_type(unsigned int drive_type, unsigned int dnr)
{
    if (!drive_match_bus(drive_type, dnr, iec_available_busses()))
        return 0;

    if (DRIVE_IS_DUAL(drive_type)) {
        if (dnr > 0) {
            /* A second dual drive is not supported.  */
            return 0;
        } else {
            if (drive[1].type != DRIVE_TYPE_NONE)
                /* Disable dual drive if second drive is enabled.  */
                return 0;
        }
    }

    /* If the first drive is dual no second drive is supported at all.  */
    if (DRIVE_IS_DUAL(drive[0].type) && dnr > 0)
        return 0;

    if (machine_drive_rom_check_loaded(drive_type) < 0)
        return 0;

    return 1;
}

int drive_check_extend_policy(unsigned int drive_type)
{
    if ((drive_type == DRIVE_TYPE_1541) ||
        (drive_type == DRIVE_TYPE_1541II) ||
        (drive_type == DRIVE_TYPE_1551) ||
        (drive_type == DRIVE_TYPE_1570) ||
        (drive_type == DRIVE_TYPE_1571) ||
        (drive_type == DRIVE_TYPE_1571CR) ||
        (drive_type == DRIVE_TYPE_2031)) return 1;
    return 0;
}

int drive_check_idle_method(unsigned int drive_type)
{
    if ((drive_type == DRIVE_TYPE_1541) ||
        (drive_type == DRIVE_TYPE_1541II)) return 1;
    return 0;
}

int drive_check_parallel_cable(unsigned int drive_type)
{
    if ((drive_type == DRIVE_TYPE_1541) ||
        (drive_type == DRIVE_TYPE_1541II)) return 1;
    return 0;
}

/* ------------------------------------------------------------------------- */

/* Update the status bar in the UI.  */
void drive_update_ui_status(void)
{
    int i;

    if (console_mode || vsid_mode) {
        return;
    }

    /* Update the LEDs and the track indicators.  */
    for (i = 0; i < 2; i++) {
        if (drive[i].enable
            || ((i == 1) && drive[0].enable && DRIVE_IS_DUAL(drive[0].type))) {
            int my_led_status = 0;

            /* Actually update the LED status only if the `trap idle'
               idling method is being used, as the LED status could be
               incorrect otherwise.  */

            if (drive[i].idling_method != DRIVE_IDLE_SKIP_CYCLES)
                my_led_status = drive[i].led_status;

            if (my_led_status != drive[i].old_led_status) {
                ui_display_drive_led(i, my_led_status);
                drive[i].old_led_status = my_led_status;
            }

            if (drive[i].current_half_track != drive[i].old_half_track) {
                drive[i].old_half_track = drive[i].current_half_track;
#ifdef __riscos
                ui_display_drive_track_int(i, drive[i].current_half_track);
#else
                ui_display_drive_track(i, (i < 2 && drive[0].enable
                                       && DRIVE_IS_DUAL(drive[0].type))
                                       ? 0 : 8,
                                       ((float)drive[i].current_half_track
                                       / 2.0));
#endif
            }
        }
    }
}

/* This is called at every vsync.  */
void drive_vsync_hook(void)
{
    unsigned int dnr;

    drive_update_ui_status();

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        if (drive[dnr].idling_method != DRIVE_IDLE_SKIP_CYCLES
            && drive[dnr].enable)
            drivecpu_execute(drive_context[dnr], maincpu_clk);
    }

    machine_drive_vsync_hook();
}

/* ------------------------------------------------------------------------- */

int drive_num_leds(unsigned int dnr)
{
    if (DRIVE_IS_OLDTYPE(drive[dnr].type)) {
        return 2;
    }

    if ((dnr == 1) && DRIVE_IS_DUAL(drive[0].type)) {
        return 2;
    }

    return 1;
}


static void drive_setup_context_for_drive(drive_context_t *drv,
                                          unsigned int dnr)
{
    /*static drive_t drive[2];*/

    drv->mynumber = dnr;
    drv->drive = &drive[dnr];
    drv->clk_ptr = &drive_clk[dnr];

    drive_cpu_setup_context(drv);
    machine_drive_setup_context(drv);
}

void drive_setup_context(void)
{
    unsigned int dnr;

    drive_context[0] = &drive0_context;
    drive_context[1] = &drive1_context;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++)
        drive_setup_context_for_drive(drive_context[dnr], dnr);
}

struct drive_s *drive_get_drive(unsigned int dnr)
{
    return drive_context[dnr]->drive;
}

