/*
 * driverom.c
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

#include "drive.h"
#include "driverom.h"
#include "log.h"
#include "machine-drive.h"
#include "resources.h"
#include "sysfile.h"
#include "traps.h"
#include "types.h"

/* patch for 1541 driverom at $EAAF */
/* skips RAM and ROM check for fast drive reset */
/*
static unsigned char rompatch[26]=
{
    0x9D, 0x00, 0x01,
    0x9D, 0x00, 0x02,
    0x9D, 0x00, 0x03,
    0x9D, 0x00, 0x04,
    0x9D, 0x00, 0x05,
    0x9D, 0x00, 0x06,
    0x9D, 0x00, 0x07,
    0xE8,
    0xD0, 0xE6,
    0xF0, 0x59
};
*/

/* Logging goes here.  */
static log_t driverom_log;

/* If nonzero, we are far enough in init that we can load ROMs.  */
int drive_rom_load_ok = 0;


int driverom_load_images(void)
{
    drive_rom_load_ok = 1;

    machine_drive_rom_load();

    if (machine_drive_rom_check_loaded(DRIVE_TYPE_ANY) < 0) {
        log_error(driverom_log,
                  "No ROM image found at all!  "
                  "Hardware-level emulation is not available.");
        return -1;
    }

    return 0;
}

static void driverom_fix_checksum(drive_t *drive)
{
    int i, j;

    switch (drive->type) {
    case DRIVE_TYPE_1541:
    case DRIVE_TYPE_1541II:
	{
	    DWORD sum = (DWORD)-0xc0;
	    drive->rom[0x4001] = 0xff;
	    for (i = 0; i < 0x2000; i++) {
		sum += drive->rom[i ^ 0x5f00];
	    }
	    drive->rom[0x4001] = ~(sum % 255);

	    sum = (DWORD)-0xe0;
	    drive->rom[0x7ee6] = 0xff;
	    for (i = 0; i < 0x2000; i++) {
		sum += drive->rom[i ^ 0x7f00];
	    }
	    drive->rom[0x7ee6] = ~(sum % 255);
	}
	break;
    case DRIVE_TYPE_1551:
	{
	    DWORD sum = 0xfe;
	    drive->rom[0x4000] = 0xff;
	    for (i = 0x0; i < 0x4000; i++) {
		sum += drive->rom[i ^ 0x7f00];
	    }
	    drive->rom[0x4000] = ~(sum % 255);
	}
	break;
    case DRIVE_TYPE_1570:
	{
	    DWORD sum = 0xff;
	    drive->rom[0x4000] = 0xff;
	    for (i = 0x102; i < 0x8000; i++) {
		sum += drive->rom[i];
	    }
	    drive->rom[0x4000] = ~(sum % 255);
	}
        break;
    case DRIVE_TYPE_1571:
    case DRIVE_TYPE_1571CR:
	{
	    DWORD sum = 0xfe;
	    drive->rom[0x4000] = 0xff;
	    for (i = 2; i < 0x8000; i++) {
		sum += drive->rom[i];
	    }
	    drive->rom[0x4000] = ~(sum % 255);
	}
        break;
    case DRIVE_TYPE_1581:
	{
	    DWORD sum = 0xff;
	    drive->rom[0x0002] = 0xff;
	    for (i = 2; i < 0x8000; i++) {
		sum += drive->rom[i];
	    }
	    drive->rom[0x0002] = ~(sum % 255);
	}
        break;
    case DRIVE_TYPE_2000:
    case DRIVE_TYPE_4000:
	{
	    WORD sum = 0;
	    for (i = 4; i < 0x8000; i++) {
		sum += drive->rom[i];
	    }
	    drive->rom[2] = sum;
	    drive->rom[3] = sum >> 8;
	}
        break;
    case DRIVE_TYPE_2031:
	{
	    DWORD sum = (DWORD)-0xc0;
	    drive->rom[0x4000] = 0xff;
	    for (i = 0; i < 0x2000; i++) {
		sum += drive->rom[i ^ 0x5f00];
	    }
	    drive->rom[0x4000] = ~(sum % 255);

	    sum = (DWORD)-0xe0;
	    drive->rom[0x7f35] = 0xff;
	    for (i = 0; i < 0x2000; i++) {
		sum += drive->rom[i ^ 0x7f00];
	    }
	    drive->rom[0x7f35] = ~(sum % 255);
	}
        break;
    }
    switch (drive->type) {
    case DRIVE_TYPE_1570:
    case DRIVE_TYPE_1571:
    case DRIVE_TYPE_1571CR:
	{
	    WORD sum = 0;
	    BYTE m, m2;
	    for (i = 6; i < 0x8003; i++) {
		switch (i) {
		case 0x8000:
		    m = sum;
		    break;
		case 0x8001:
		    m = sum >> 8;
		    break;
		case 0x8002:
		    break;
		default:
		    m = drive->rom[i];
		}
		for (j = 0; j < 8; j++) {
		    m2 = m ^ (sum >> 8) ^ (sum >> 11) ^ (sum >> 15) ^ (sum >> 6);
		    m = (m >> 1) | ((sum >> 8) & 0x80);
		    sum = (sum << 1) | (m2 & 1);
		}
	    }
	    drive->rom[0] = sum;
	    drive->rom[1] = sum >> 8;
	}
        break;
    case DRIVE_TYPE_1581:
	{
	    WORD sum = 0xffff, m, m2;
	    for (i = 2; i < 0x8000; i += 2) {
		m = (drive->rom[i] << 8) | drive->rom[i + 1];
		for (j = 0; j < 16; j++) {
		    m2 = m ^ sum;
		    m <<= 1;
		    sum <<= 1;
		    if (m2 & 0x8000) {
			sum ^= 0x1021;
		    }
		}
	    }
	    drive->rom[0] = sum;
	    drive->rom[1] = sum >> 8;
	}
        break;
    }
}

void driverom_initialize_traps(drive_t *drive, int save)
{
    if (save && drive->type == DRIVE_TYPE_1551) {
        drive->rom_idle_trap[0] = drive->rom[0xeabf - 0x8000];
        drive->rom_idle_trap[1] = drive->rom[0xeac0 - 0x8000];
        drive->rom_idle_trap[2] = drive->rom[0xead0 - 0x8000];
    }
    switch (drive->type) {
    case DRIVE_TYPE_1541:
    case DRIVE_TYPE_1541II:
    case DRIVE_TYPE_1570:
    case DRIVE_TYPE_1571:
    case DRIVE_TYPE_1571CR:
        drive->trap = 0xec9b;
        drive->trapcont = 0xebff;
        break;
    case DRIVE_TYPE_1551:
        drive->trap = 0xead9;
        drive->trapcont = 0xeabd;
        if (drive->idling_method == DRIVE_IDLE_TRAP_IDLE) {
            drive->rom[0xeabf - 0x8000] = 0xea;
            drive->rom[0xeac0 - 0x8000] = 0xea;
            drive->rom[0xead0 - 0x8000] = 0x08;
        } else {
            drive->rom[0xeabf - 0x8000] = drive->rom_idle_trap[0];
            drive->rom[0xeac0 - 0x8000] = drive->rom_idle_trap[1];
            drive->rom[0xead0 - 0x8000] = drive->rom_idle_trap[2];
        }
        break;
    case DRIVE_TYPE_1581:
        drive->trap = 0xb158;
        drive->trapcont = 0xb105;
        break;
    case DRIVE_TYPE_2000:
        drive->trap = 0xf3c0;
        drive->trapcont = 0xf368;
        break;
    case DRIVE_TYPE_4000:
        drive->trap = 0xf3ec;
        drive->trapcont = 0xf394;
        break;
    case DRIVE_TYPE_2031:
        drive->trap = 0xece9;
        drive->trapcont = 0xec4d;
        break;
    default:
        drive->trap = -1;
        drive->trapcont = -1;
    }
    if (drive->trap >=0
        && drive->rom[drive->trap - 0x8000 + 1] == (drive->trapcont & 0xff)
        && drive->rom[drive->trap - 0x8000 + 2] == (drive->trapcont >> 8)) {

        if (drive->idling_method == DRIVE_IDLE_TRAP_IDLE
            && drive->rom[drive->trap - 0x8000] == 0x4c) {
            drive->rom[drive->trap - 0x8000] = TRAP_OPCODE;
        }
        if (drive->idling_method != DRIVE_IDLE_TRAP_IDLE
            && drive->rom[drive->trap - 0x8000] == TRAP_OPCODE) {
            drive->rom[drive->trap - 0x8000] = 0x4c;
            drive->trap = -1;
            drive->trapcont = -1;
        }
    } else {
        drive->trap = -1;
        drive->trapcont = -1;
    }
    driverom_fix_checksum(drive);
}

void driverom_init(void)
{
    driverom_log = log_open("DriveROM"); 
}

