/*
 * serial.h - Serial device implementation.
 *
 * Written by
 *  Teemu Rantanen <tvr@cs.hut.fi>
 *  Andr� Fachat <a.fachat@physik.tu-chemnitz.de>
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

#ifndef _SERIAL_H
#define _SERIAL_H

#include "types.h"

/* Serial Error Codes. */

#define SERIAL_OK               0
#define SERIAL_WRITE_TIMEOUT    1
#define SERIAL_READ_TIMEOUT     2
#define SERIAL_FILE_NOT_FOUND   64
#define SERIAL_NO_DEVICE        128

#define SERIAL_ERROR            (2)
#define SERIAL_EOF              (64)

/* Printers. */
#define DT_ASCII                0       /* No printer commands nor graphics */
#define DT_MPS803               1
#define DT_STAR10CCL            2

/* Store name here for serial-open.  */
#define SERIAL_NAMELENGTH 255

#define SERIAL_MAXDEVICES 16

#define SERIAL_DEVICE_VIRT 0
#define SERIAL_DEVICE_FS   1
#define SERIAL_DEVICE_REAL 2
#define SERIAL_DEVICE_RAW  3

struct disk_image_s;
struct trap_s;
struct vdrive_s;

typedef struct serial_s
{
    int inuse;
    int isopen[16]; /* isopen flag for each secondary address */
    struct disk_image_s *image; /* pointer to the disk image data  */
    char *name; /* name of the device */
    int (*getf)(struct vdrive_s *, BYTE *, unsigned int);
    int (*putf)(struct vdrive_s *, BYTE, unsigned int);
    int (*openf)(struct vdrive_s *, const char *, int, unsigned int);
    int (*closef)(struct vdrive_s *, unsigned int);
    void (*flushf)(struct vdrive_s *, unsigned int);
    BYTE nextbyte[16]; /* next byte to send, per sec. addr. */
    char nextok[16]; /* flag if nextbyte is valid */

    int nextst[16];
    unsigned int device;

    /* The PET hardware emulation can be interrupted while
       transferring a byte. Thus we also have to save the byte
       and status last sent, to be able to send it again. */
    BYTE lastbyte[16];
    char lastok[16];
    int lastst[16];

} serial_t;

extern int serial_init(const struct trap_s *trap_list);
extern int serial_resources_init(void);
extern int serial_cmdline_options_init(void);
extern void serial_shutdown(void);
extern int serial_install_traps(void);
extern int serial_remove_traps(void);
extern void serial_set_truedrive(int flag);
extern int serial_attach_device(unsigned int unit, const char *name,
                                int (*getf)(struct vdrive_s *,
                                BYTE *, unsigned int),
                                int (*putf)(struct vdrive_s *, BYTE,
                                unsigned int),
                                int (*openf)(struct vdrive_s *,
                                const char *, int,
                                unsigned int),
                                int (*closef)(struct vdrive_s *, unsigned int),
                                void (*flushf)(struct vdrive_s *,
                                unsigned int));
extern int serial_detach_device(unsigned int unit);

extern BYTE serial_get_st(void);
extern void serial_set_st(BYTE st);

extern void (*attention_callback_func)(void);
extern void (*eof_callback_func)(void);

extern void serial_trap_init(WORD tmpin);
extern int serial_trap_attention(void);
extern int serial_trap_send(void);
extern int serial_trap_receive(void);
extern int serial_trap_ready(void);
extern void serial_traps_reset(void);


extern void serial_set_eof_callback(void (*func)(void));
extern void serial_set_attention_callback(void (*func)(void));

extern int serial_realdevice_enable(void);
extern void serial_realdevice_disable(void);

extern int serial_iec_lib_directory(unsigned int unit, const char *pattern,
                                    BYTE **buf);
extern int serial_iec_lib_read_sector(unsigned int unit, unsigned int track,
                                      unsigned int sector, BYTE *buf);
extern int serial_iec_lib_write_sector(unsigned int unit, unsigned int track,
                                       unsigned int sector, BYTE *buf);

extern unsigned int serial_device_get_fsimage_state(unsigned int unit);
extern unsigned int serial_device_get_realdevice_state(unsigned int unit);
extern serial_t *serial_device_get(unsigned int unit);
extern unsigned int serial_device_type_get(unsigned int unit);
extern void serial_device_type_set(unsigned int type, unsigned int unit);

extern int serial_truedrive;

#endif

