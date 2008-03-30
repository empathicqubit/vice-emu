/*
 * attach.c - File system attach management.
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

#include "attach.h"
#include "cmdline.h"
#include "diskimage.h"
#include "driveimage.h"
#include "event.h"
#include "fsdevice.h"
#include "fliplist.h"
#include "lib.h"
#include "log.h"
#include "machine-drive.h"
#include "resources.h"
#include "serial.h"
#include "snapshot.h"
#ifdef HAS_TRANSLATION
#include "translate.h"
#endif
#include "types.h"
#include "ui.h"
#include "vdrive-bam.h"
#include "vdrive-iec.h"
#include "vdrive.h"


typedef struct {
    serial_t *serial;
    vdrive_t *vdrive;
} file_system_t;


static file_system_t file_system[4];

static log_t attach_log = LOG_DEFAULT;

static unsigned int attach_device_readonly_enabled[4];
static unsigned int file_system_device_enabled[4];

static int set_attach_device_readonly(resource_value_t v, void *param);
static int set_file_system_device(resource_value_t v, void *param);

static void detach_disk_image(disk_image_t *image, vdrive_t *floppy,
                              unsigned int unit);
static void detach_disk_image_and_free(disk_image_t *image, vdrive_t *floppy,
                                       unsigned int unit);
static int attach_disk_image(disk_image_t **imgptr, vdrive_t *floppy,
                             const char *filename, unsigned int unit,
                             unsigned int devicetype);

static const resource_t resources[] = {
    { "AttachDevice8Readonly", RES_INTEGER, (resource_value_t)0,
      (void *)&attach_device_readonly_enabled[0],
      set_attach_device_readonly, (void *)8 },
    { "AttachDevice9Readonly", RES_INTEGER, (resource_value_t)0,
      (void *)&attach_device_readonly_enabled[1],
      set_attach_device_readonly, (void *)9 },
    { "AttachDevice10Readonly", RES_INTEGER, (resource_value_t)0,
      (void *)&attach_device_readonly_enabled[2],
      set_attach_device_readonly, (void *)10 },
    { "AttachDevice11Readonly", RES_INTEGER, (resource_value_t)0,
      (void *)&attach_device_readonly_enabled[3],
      set_attach_device_readonly, (void *)11 },
    { "FileSystemDevice8", RES_INTEGER, (resource_value_t)ATTACH_DEVICE_FS,
      (void *)&file_system_device_enabled[0],
      set_file_system_device, (void *)8 },
    { "FileSystemDevice9", RES_INTEGER, (resource_value_t)ATTACH_DEVICE_FS,
      (void *)&file_system_device_enabled[1],
      set_file_system_device, (void *)9 },
    { "FileSystemDevice10", RES_INTEGER, (resource_value_t)ATTACH_DEVICE_FS,
      (void *)&file_system_device_enabled[2],
      set_file_system_device, (void *)10 },
    { "FileSystemDevice11", RES_INTEGER, (resource_value_t)ATTACH_DEVICE_FS,
      (void *)&file_system_device_enabled[3],
      set_file_system_device, (void *)11 },
    { NULL }
};

int file_system_resources_init(void)
{
    return resources_register(resources);
}

/* ------------------------------------------------------------------------- */

#ifdef HAS_TRANSLATION
static const cmdline_option_t cmdline_options[] = {
    { "-device8", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice8",
      (void *)ATTACH_DEVICE_FS, IDCLS_P_TYPE,
      IDCLS_SET_DEVICE_TYPE_8 },
    { "-device9", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice9",
      (void *)ATTACH_DEVICE_FS, IDCLS_P_TYPE,
      IDCLS_SET_DEVICE_TYPE_9 },
    { "-device10", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice10",
      (void *)ATTACH_DEVICE_FS, IDCLS_P_TYPE,
      IDCLS_SET_DEVICE_TYPE_10 },
    { "-device11", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice11",
      (void *)ATTACH_DEVICE_FS, IDCLS_P_TYPE,
      IDCLS_SET_DEVICE_TYPE_11 },
    { "-attach8ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice8Readonly",
      (resource_value_t)1,
      0, IDCLS_ATTACH_READ_ONLY_8 },
    { "-attach8rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice8Readonly",
      (resource_value_t)0,
      0, IDCLS_ATTACH_READ_WRITE_8 },
    { "-attach9ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice9Readonly",
      (resource_value_t)1,
      0, IDCLS_ATTACH_READ_ONLY_9 },
    { "-attach9rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice9Readonly",
      (resource_value_t)0,
      0, IDCLS_ATTACH_READ_WRITE_9 },
    { "-attach10ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice10Readonly",
      (resource_value_t)1,
      0, IDCLS_ATTACH_READ_ONLY_10 },
    { "-attach10rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice10Readonly",
      (resource_value_t)0,
      0, IDCLS_ATTACH_READ_WRITE_10 },
    { "-attach11ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice11Readonly",
      (resource_value_t)1,
      0, IDCLS_ATTACH_READ_ONLY_11 },
    { "-attach11rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice11Readonly",
      (resource_value_t)0,
      0, IDCLS_ATTACH_READ_WRITE_11 },
    { NULL }
};
#else
static const cmdline_option_t cmdline_options[] = {
    { "-device8", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice8",
      (void *)ATTACH_DEVICE_FS, N_("<type>"),
      N_("Set device type for device #8 (0: NONE, 1: FS, 2: REAL, 3: RAW)") },
    { "-device9", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice9",
      (void *)ATTACH_DEVICE_FS, N_("<type>"),
      N_("Set device type for device #9 (0: NONE, 1: FS, 2: REAL, 3: RAW)") },
    { "-device10", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice10",
      (void *)ATTACH_DEVICE_FS, N_("<type>"),
      N_("Set device type for device #10 (0: NONE, 1: FS, 2: REAL, 3: RAW)") },
    { "-device11", SET_RESOURCE, 1, NULL, NULL, "FileSystemDevice11",
      (void *)ATTACH_DEVICE_FS, N_("<type>"),
      N_("Set device type for device #11 (0: NONE, 1: FS, 2: REAL, 3: RAW)") },
    { "-attach8ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice8Readonly",
      (resource_value_t)1,
      NULL, N_("Attach disk image for drive #8 read only") },
    { "-attach8rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice8Readonly",
      (resource_value_t)0,
      NULL, N_("Attach disk image for drive #8 read write (if possible)") },
    { "-attach9ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice9Readonly",
      (resource_value_t)1,
      NULL, N_("Attach disk image for drive #9 read only") },
    { "-attach9rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice9Readonly",
      (resource_value_t)0,
      NULL, N_("Attach disk image for drive #9 read write (if possible)") },
    { "-attach10ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice10Readonly",
      (resource_value_t)1,
      NULL, N_("Attach disk image for drive #10 read only") },
    { "-attach10rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice10Readonly",
      (resource_value_t)0,
      NULL, N_("Attach disk image for drive #10 read write (if possible)") },
    { "-attach11ro", SET_RESOURCE, 0, NULL, NULL, "AttachDevice11Readonly",
      (resource_value_t)1,
      NULL, N_("Attach disk image for drive #11 read only") },
    { "-attach11rw", SET_RESOURCE, 0, NULL, NULL, "AttachDevice11Readonly",
      (resource_value_t)0,
      NULL, N_("Attach disk image for drive #11 read write (if possible)") },
    { NULL }
};
#endif

int file_system_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}

/* ------------------------------------------------------------------------- */

static int file_system_set_serial_hooks(unsigned int unit, unsigned int fs)
{
    if (!fs) {
        if (vdrive_iec_attach(unit, "CBM Disk Drive")) {
            log_error(attach_log,
                      "Could not initialize vdrive emulation for device #%i.",
                      unit);
            return -1;
        }
    } else {
        if (fsdevice_attach(unit, "FS Drive")) {
            log_error(attach_log,
                      "Could not initialize FS drive for device #%i.",
                      unit);
            return -1;
        }
    }
    return 0;
}

void file_system_init(void)
{
    unsigned int i;

    attach_log = log_open("Attach");

    for (i = 0; i < 4; i++) {
        file_system[i].serial = serial_device_get(i + 8);;
        file_system[i].vdrive = (vdrive_t *)lib_calloc(1, sizeof(vdrive_t));
        switch (file_system_device_enabled[i]) {
          case ATTACH_DEVICE_NONE:
            vdrive_device_setup(file_system[i].vdrive, i + 8);
            serial_device_type_set(SERIAL_DEVICE_VIRT, i + 8);
            break;
          case ATTACH_DEVICE_FS:
            vdrive_device_setup(file_system[i].vdrive, i + 8);
            serial_device_type_set(SERIAL_DEVICE_FS, i + 8);
            break;
          case ATTACH_DEVICE_REAL:
            vdrive_device_setup(file_system[i].vdrive, i + 8);
            serial_device_type_set(SERIAL_DEVICE_REAL, i + 8);
            break;
          case ATTACH_DEVICE_RAW:
            vdrive_device_setup(file_system[i].vdrive, i + 8);
            serial_device_type_set(SERIAL_DEVICE_RAW, i + 8);
            break;
        }
        file_system_set_serial_hooks(i + 8, file_system_device_enabled[i]);
    }
}

void file_system_shutdown(void)
{
    unsigned int i;

    for (i = 0; i < 4; i++) {
        vdrive_device_shutdown(file_system[i].vdrive);
        lib_free(file_system[i].vdrive);
    }
}

struct vdrive_s *file_system_get_vdrive(unsigned int unit)
{
    if (unit < 8 || unit > 11) {
        log_error(attach_log, "Wrong unit for vdrive");
        return NULL;
    }

    return file_system[unit - 8].vdrive;
}

const char *file_system_get_disk_name(unsigned int unit)
{
    vdrive_t *vdrive;

    vdrive = file_system_get_vdrive(unit);

    if (vdrive == NULL)
        return NULL;
    if (vdrive->image == NULL)
        return NULL;

    if (vdrive->image->device != DISK_IMAGE_DEVICE_FS)
        return NULL;

    return disk_image_fsimage_name_get(vdrive->image);
}

int file_system_bam_get_disk_id(unsigned int unit, BYTE *id)
{
    return vdrive_bam_get_disk_id(unit, id);
}

int file_system_bam_set_disk_id(unsigned int unit, BYTE *id)
{
    return vdrive_bam_set_disk_id(unit, id);
}

/* ------------------------------------------------------------------------- */

static int set_attach_device_readonly(resource_value_t v, void *param)
{
    unsigned int unit;
    const char *old_filename;
    char *new_filename;
    int rc;

    unit = (unsigned int)param;

    /* Do nothing if resource is unchanged.  */
    if (attach_device_readonly_enabled[unit - 8] == ((unsigned int)v))
        return 0;

    old_filename = file_system_get_disk_name(unit);

    /* If no disk is attached, just changed the resource.  */
    if (old_filename == NULL) {
        attach_device_readonly_enabled[unit - 8] = (unsigned int)v;
        return 0;
    }

    /* Old filename will go away after the image is detached.  */
    new_filename = lib_stralloc(old_filename);

    file_system_detach_disk(unit);
    attach_device_readonly_enabled[unit - 8] = (unsigned int)v;

    rc = file_system_attach_disk(unit, new_filename);

    lib_free(new_filename);

    return rc;
}

/* ------------------------------------------------------------------------- */

static int set_file_system_device(resource_value_t v, void *param)
{
    vdrive_t *vdrive;
    unsigned int unit, old_device_enabled;

    unit = (unsigned int)param;
    old_device_enabled = file_system_device_enabled[unit - 8];

    vdrive = file_system_get_vdrive(unit);

    switch ((unsigned int)v) {
      case ATTACH_DEVICE_NONE:
        if (old_device_enabled == ATTACH_DEVICE_REAL)
            serial_realdevice_disable();
        if (old_device_enabled == ATTACH_DEVICE_RAW)
            detach_disk_image(vdrive->image, vdrive, unit);
        if (vdrive != NULL && vdrive->image == NULL) {
            vdrive_device_setup(vdrive, unit);
            serial_device_type_set(SERIAL_DEVICE_VIRT, unit);
            file_system_set_serial_hooks(unit, 0);
        }
        break;
      case ATTACH_DEVICE_FS:
        if (old_device_enabled == ATTACH_DEVICE_REAL)
            serial_realdevice_disable();
        if (old_device_enabled == ATTACH_DEVICE_RAW)
            detach_disk_image(vdrive->image, vdrive, unit);
        if (vdrive != NULL && vdrive->image == NULL) {
            vdrive_device_setup(vdrive, unit);
            serial_device_type_set(SERIAL_DEVICE_FS, unit);
            file_system_set_serial_hooks(unit, 1);
        }
        break;
#ifdef HAVE_OPENCBM
      case ATTACH_DEVICE_REAL:
        if (old_device_enabled == ATTACH_DEVICE_RAW)
            detach_disk_image(vdrive->image, vdrive, unit);
        if (serial_realdevice_enable() < 0) {
            log_warning(attach_log, "Falling back to fs device.");
            return set_file_system_device((resource_value_t)ATTACH_DEVICE_FS,
                                          param);
        }
        if (vdrive != NULL && vdrive->image != NULL) {
            detach_disk_image_and_free(vdrive->image, vdrive, unit);
            ui_display_drive_current_image(unit - 8, "");
            vdrive_device_setup(vdrive, unit);
        }
        serial_device_type_set(SERIAL_DEVICE_REAL, unit);
        break;
#endif
#ifdef HAVE_RAWDRIVE
      case ATTACH_DEVICE_RAW:
        if (old_device_enabled == ATTACH_DEVICE_REAL)
            serial_realdevice_disable();
        if (vdrive != NULL && vdrive->image != NULL) {
            detach_disk_image_and_free(vdrive->image, vdrive, unit);
            ui_display_drive_current_image(unit - 8, "");
            vdrive_device_setup(vdrive, unit);
        }
        attach_disk_image(&(vdrive->image), vdrive, "DUMMY", unit,
                          ATTACH_DEVICE_RAW);
        file_system_set_serial_hooks(unit, 0);
        serial_device_type_set(SERIAL_DEVICE_RAW, unit);
        break;
#endif
      default:
        return -1;
    }

    file_system_device_enabled[unit - 8] = (unsigned int)v;

    return 0;
}

/* ------------------------------------------------------------------------- */

static void detach_disk_image(disk_image_t *image, vdrive_t *floppy,
                              unsigned int unit)
{
    if (image != NULL) {
        switch (unit) {
          case 8:
            machine_drive_image_detach(image, 8);
            drive_image_detach(image, 8);
            vdrive_detach_image(image, 8, floppy);
            break;
          case 9:
            machine_drive_image_detach(image, 9);
            drive_image_detach(image, 9);
            vdrive_detach_image(image, 9, floppy);
            break;
          case 10:
            machine_drive_image_detach(image, 10);
            drive_image_detach(image, 10);
            vdrive_detach_image(image, 10, floppy);
            break;
          case 11:
            machine_drive_image_detach(image, 11);
            drive_image_detach(image, 11);
            vdrive_detach_image(image, 11, floppy);
            break;
        }
        disk_image_close(image);
        disk_image_media_destroy(image);
    }
}

static void detach_disk_image_and_free(disk_image_t *image, vdrive_t *floppy,
                                       unsigned int unit)
{
    disk_image_t *oldimg = floppy->image;
    
    detach_disk_image(image, floppy, unit);
    
    if ((image != NULL) && (image == oldimg))
        lib_free(image);
}

static int attach_disk_image(disk_image_t **imgptr, vdrive_t *floppy,
                             const char *filename, unsigned int unit,
                             unsigned int devicetype)
{
    disk_image_t *image;
    disk_image_t new_image;
    int err = -1;

    if (filename == NULL) {
        log_error(attach_log, "No name, cannot attach floppy image.");
        return -1;
    }

    new_image.gcr = NULL;
    new_image.read_only = attach_device_readonly_enabled[unit - 8];

    switch (devicetype) {
      case ATTACH_DEVICE_NONE:
      case ATTACH_DEVICE_FS:
        new_image.device = DISK_IMAGE_DEVICE_FS;
        break;
      case ATTACH_DEVICE_RAW:
        new_image.device = DISK_IMAGE_DEVICE_RAW;
        break;
    }

    disk_image_media_create(&new_image);

    switch (devicetype) {
      case ATTACH_DEVICE_NONE:
      case ATTACH_DEVICE_FS:
        disk_image_fsimage_name_set(&new_image, lib_stralloc(filename));
        break;
      case ATTACH_DEVICE_RAW:
        disk_image_rawimage_driver_name_set(&new_image);
        break;
    }

    if (disk_image_open(&new_image) < 0) {
        disk_image_media_destroy(&new_image);
        return -1;
    }

    detach_disk_image_and_free(*imgptr, floppy, unit);

    *imgptr = (disk_image_t *)lib_malloc(sizeof(disk_image_t));
    image = *imgptr;

    memcpy(image, &new_image, sizeof(disk_image_t));

    switch (unit) {
      case 8:
        err = drive_image_attach(image, 8);
        err &= vdrive_attach_image(image, 8, floppy);
        err &= machine_drive_image_attach(image, 8);
        break;
      case 9:
        err = drive_image_attach(image, 9);
        err &= vdrive_attach_image(image, 9, floppy);
        err &= machine_drive_image_attach(image, 9);
        break;
      case 10:
        err = drive_image_attach(image, 10);
        err &= vdrive_attach_image(image, 10, floppy);
        err &= machine_drive_image_attach(image, 10);
        break;
      case 11:
        err = drive_image_attach(image, 11);
        err &= vdrive_attach_image(image, 11, floppy);
        err &= machine_drive_image_attach(image, 11);
        break;
    }
    if (err) {
        disk_image_close(image);
        disk_image_media_destroy(image);
        lib_free(image);
        *imgptr = NULL;
    }
    return err;
}

/* ------------------------------------------------------------------------- */

static int file_system_attach_disk_internal(unsigned int unit, const char *filename)
{
    vdrive_t *vdrive;

    vdrive = file_system_get_vdrive(unit);
    /* FIXME: Is this clever?  */
    vdrive_device_setup(vdrive, unit);
    serial_device_type_set(SERIAL_DEVICE_VIRT, unit);

    if (attach_disk_image(&(vdrive->image), vdrive, filename, unit,
        file_system_device_enabled[unit - 8]) < 0) {
        return -1;
    } else {
        file_system_set_serial_hooks(unit, 0);
        fliplist_set_current(unit, filename);
        ui_display_drive_current_image(unit - 8, filename);
    }
    
    event_record_attach_image(unit, filename, vdrive->image->read_only);

    return 0;
}

int file_system_attach_disk(unsigned int unit, const char *filename)
{
   if (event_playback_active())
        return -1;

   return file_system_attach_disk_internal(unit, filename);
}

static void file_system_detach_disk_single(unsigned int unit)
{
    vdrive_t *vdrive;

    vdrive = file_system_get_vdrive(unit);
    if (vdrive != NULL)
        detach_disk_image_and_free(vdrive->image, vdrive, (unsigned int)unit);

    set_file_system_device((resource_value_t)
                           file_system_device_enabled[unit - 8], (void *)unit);
    ui_display_drive_current_image(unit - 8, "");
}

static void file_system_detach_disk_internal(int unit)
{
    char event_data[2];

    if (unit < 0) {
        unsigned int i;

        for (i = 8; i <= 11; i++)
            file_system_detach_disk_single(i);
    } else {
        if (unit >= 8 && unit <= 11)
            file_system_detach_disk_single((unsigned int)unit);
        else
            log_error(attach_log, "Cannot detach unit %i.", unit);
    }

    event_data[0] = (char)unit;
    event_data[1] = 0;

    event_record(EVENT_ATTACHDISK, (void *)event_data, 2);
}

void file_system_detach_disk(int unit)
{
   if (event_playback_active())
        return;

   file_system_detach_disk_internal(unit);
}

void file_system_detach_disk_shutdown(void)
{
    vdrive_t *vdrive;
    unsigned int i;

    for (i = 0; i <= 3; i++) {
        vdrive = file_system_get_vdrive(i + 8);
        if (vdrive != NULL) {
            if (file_system_device_enabled[i] == ATTACH_DEVICE_REAL)
                serial_realdevice_disable();
            else
                detach_disk_image_and_free(vdrive->image, vdrive, i + 8);
        }
    }
}

void file_system_event_playback(unsigned int unit, const char *filename)
{
    if (filename == NULL || filename[0] == 0)
        file_system_detach_disk_internal(unit);
    else
        file_system_attach_disk_internal(unit, filename);
}

