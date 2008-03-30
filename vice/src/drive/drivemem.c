/*
 * drivemem.c - Drive memory handling.
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

#include "drive.h"
#include "driverom.h"
#include "drivetypes.h"
#include "fdc.h"
#include "log.h"
#include "machine-drive.h"
#include "mem.h"
#include "mon.h"
#include "types.h"
#include "utils.h"
#include "viad.h"
#include "wd1770.h"


/* ------------------------------------------------------------------------- */
/* Common memory access.  */

static BYTE REGPARM2 drive_read_ram(drive_context_t *drv, ADDRESS address)
{
    /* FIXME: This breaks the 1541 RAM mirror!  */
    return drv->cpud.drive_ram[address & 0x1fff];
}

static void REGPARM3 drive_store_ram(drive_context_t *drv, ADDRESS address,
                                     BYTE value)
{
    /* FIXME: This breaks the 1541 RAM mirror!  */
    drv->cpud.drive_ram[address & 0x1fff] = value;
}

BYTE REGPARM2 drive_read_rom(drive_context_t *drv, ADDRESS address)
{
    return drv->drive_ptr->rom[address & 0x7fff];
}

static BYTE REGPARM2 drive_read_free(drive_context_t *drv, ADDRESS address)
{
    return address >> 8;
}

static void REGPARM3 drive_store_free(drive_context_t *drv, ADDRESS address,
                                      BYTE value)
{
    return;
}

/* ------------------------------------------------------------------------- */
/* Zero page access.  */

static BYTE REGPARM2 drive_read_zero(drive_context_t *drv, ADDRESS address)
{
    return drv->cpud.drive_ram[address & 0xff];
}

static void REGPARM3 drive_store_zero(drive_context_t *drv, ADDRESS address,
                                      BYTE value)
{
    drv->cpud.drive_ram[address & 0xff] = value;
}

/* ------------------------------------------------------------------------- */
/* Watchpoint memory access.  */

static BYTE REGPARM2 drive_read_watch(drive_context_t *drv, ADDRESS address)
{
    mon_watch_push_load_addr(address, drv->cpu.monspace);
    return drv->cpud.read_func_nowatch[address>>8](drv,address);
}

static void REGPARM3 drive_store_watch(drive_context_t *drv, ADDRESS address,
                                       BYTE value)
{
    mon_watch_push_store_addr(address, drv->cpu.monspace);
    drv->cpud.store_func_nowatch[address>>8](drv,address, value);
}

/* ------------------------------------------------------------------------- */

#ifdef _MSC_VER
#pragma optimize("",off)
#endif

void drive_mem_init(drive_context_t *drv, unsigned int type)
{
    int i;

    for (i = 0; i < 0x101; i++) {
        drv->cpud.read_func_watch[i] = drive_read_watch;
        drv->cpud.store_func_watch[i] = drive_store_watch;
        drv->cpud.read_func_nowatch[i] = drive_read_free;
        drv->cpud.store_func_nowatch[i] = drive_store_free;
    }

    machine_drive_mem_init(drv, type);

    if (type == DRIVE_TYPE_1541 || type == DRIVE_TYPE_1541II
        || type == DRIVE_TYPE_1551 || type == DRIVE_TYPE_1571
        || type == DRIVE_TYPE_1581 || type == DRIVE_TYPE_2031) {

        drv->cpu.pageone = drv->cpud.drive_ram + 0x100;

        if (type != DRIVE_TYPE_1551) {
            drv->cpud.read_func_nowatch[0] = drive_read_zero;
            drv->cpud.store_func_nowatch[0] = drive_store_zero;
        }

        /* Setup drive RAM.  */
        for (i = 0x01; i < 0x08; i++) {
            drv->cpud.read_func_nowatch[i] = drive_read_ram;
            drv->cpud.store_func_nowatch[i] = drive_store_ram;
        }

        if (type == DRIVE_TYPE_1581)
            for (i = 0x08; i < 0x20; i++) {
                drv->cpud.read_func_nowatch[i] = drive_read_ram;
                drv->cpud.store_func_nowatch[i] = drive_store_ram;
            }
    }

    /* Setup 1541, 1541-II and 1571 VIAs.  */
    if (type == DRIVE_TYPE_1541 || type == DRIVE_TYPE_1541II
        || type == DRIVE_TYPE_1571 || type == DRIVE_TYPE_2031) {
        for (i = 0x18; i < 0x1C; i++) {
            drv->cpud.read_func_nowatch[i] = via1d_read;
            drv->cpud.store_func_nowatch[i] = via1d_store;
        }
        for (i = 0x1C; i < 0x20; i++) {
            drv->cpud.read_func_nowatch[i] = via2d_read;
            drv->cpud.store_func_nowatch[i] = via2d_store;
        }
    }

    drv->cpud.read_func_nowatch[0x100] = drv->cpud.read_func_nowatch[0];
    drv->cpud.store_func_nowatch[0x100] = drv->cpud.store_func_nowatch[0];

    memcpy(drv->cpud.read_func, drv->cpud.read_func_nowatch,
           sizeof(drive_read_func_t *) * 0x101);
    memcpy(drv->cpud.store_func, drv->cpud.store_func_nowatch,
           sizeof(drive_store_func_t *) * 0x101);

    switch (type) {
      case DRIVE_TYPE_NONE:
        break;
      case DRIVE_TYPE_2040:
        drv->drive_ptr->rom_start = 0xe000;
        break;
      case DRIVE_TYPE_3040:
      case DRIVE_TYPE_4040:
        drv->drive_ptr->rom_start = 0xd000;
        break;
      case DRIVE_TYPE_1541II:
      case DRIVE_TYPE_1551:
      case DRIVE_TYPE_2031:
      case DRIVE_TYPE_1001:
      case DRIVE_TYPE_8050:
      case DRIVE_TYPE_8250:
        drv->drive_ptr->rom_start = 0xc000;
        break;
      case DRIVE_TYPE_1541:
      case DRIVE_TYPE_1571:
      case DRIVE_TYPE_1581:
        drv->drive_ptr->rom_start = 0x8000;
        break;
      default:
        log_error(LOG_ERR, "DRIVEMEM: Unknown drive type `%i'.", type);
    }
}

#ifdef _MSC_VER
#pragma optimize("",on)
#endif

static mem_ioreg_list_t *drive_ioreg_list_get(unsigned int type)
{
    mem_ioreg_list_t *drive_ioreg_list = NULL;

    switch (type) {
      case DRIVE_TYPE_1541:
      case DRIVE_TYPE_1541II:
        drive_ioreg_list 
            = (mem_ioreg_list_t *)xmalloc(sizeof(mem_ioreg_list_t) * 2);
        drive_ioreg_list[0].name = "VIA1";
        drive_ioreg_list[0].start = 0x1800;
        drive_ioreg_list[0].end = 0x180f;
        drive_ioreg_list[0].next = &drive_ioreg_list[1];

        drive_ioreg_list[1].name = "VIA2";
        drive_ioreg_list[1].start = 0x1c00;
        drive_ioreg_list[1].end = 0x1c0f;
        drive_ioreg_list[1].next = NULL;
        break;
      case DRIVE_TYPE_1551:
        drive_ioreg_list
            = (mem_ioreg_list_t *)xmalloc(sizeof(mem_ioreg_list_t) * 1);
        drive_ioreg_list[0].name = "TIA";
        drive_ioreg_list[0].start = 0x4000;
        drive_ioreg_list[0].end = 0x4007;
        drive_ioreg_list[0].next = NULL;
        break;
      case DRIVE_TYPE_1571:
        drive_ioreg_list
            = (mem_ioreg_list_t *)xmalloc(sizeof(mem_ioreg_list_t) * 4);
        drive_ioreg_list[0].name = "VIA1";
        drive_ioreg_list[0].start = 0x1800;
        drive_ioreg_list[0].end = 0x180f;
        drive_ioreg_list[0].next = &drive_ioreg_list[1];

        drive_ioreg_list[1].name = "VIA2";
        drive_ioreg_list[1].start = 0x1c00;
        drive_ioreg_list[1].end = 0x1c0f;
        drive_ioreg_list[1].next = &drive_ioreg_list[2];

        drive_ioreg_list[2].name = "WD1770";
        drive_ioreg_list[2].start = 0x2000;
        drive_ioreg_list[2].end = 0x2003;
        drive_ioreg_list[2].next = &drive_ioreg_list[3];

        drive_ioreg_list[3].name = "CIA";
        drive_ioreg_list[3].start = 0x4000;
        drive_ioreg_list[3].end = 0x400f;
        drive_ioreg_list[3].next = NULL;
        break;
      case DRIVE_TYPE_1581:
        drive_ioreg_list
            = (mem_ioreg_list_t *)xmalloc(sizeof(mem_ioreg_list_t) * 2);
        drive_ioreg_list[0].name = "CIA";
        drive_ioreg_list[0].start = 0x4000;
        drive_ioreg_list[0].end = 0x400f;
        drive_ioreg_list[0].next = &drive_ioreg_list[1];

        drive_ioreg_list[1].name = "WD1770";
        drive_ioreg_list[1].start = 0x6000;
        drive_ioreg_list[1].end = 0x6003;
        drive_ioreg_list[1].next = NULL;
        break;
      case DRIVE_TYPE_2031:
      case DRIVE_TYPE_2040:
      case DRIVE_TYPE_3040:
      case DRIVE_TYPE_4040:
      case DRIVE_TYPE_1001:
      case DRIVE_TYPE_8050:
      case DRIVE_TYPE_8250:
        drive_ioreg_list
            = (mem_ioreg_list_t *)xmalloc(sizeof(mem_ioreg_list_t) * 2);
        drive_ioreg_list[0].name = "RIOT1";
        drive_ioreg_list[0].start = 0x0200;
        drive_ioreg_list[0].end = 0x021f;
        drive_ioreg_list[0].next = &drive_ioreg_list[1];

        drive_ioreg_list[1].name = "RIOT2";
        drive_ioreg_list[1].start = 0x0280;
        drive_ioreg_list[1].end = 0x029f;
        drive_ioreg_list[1].next = NULL;
        break;
      default:
        log_error(LOG_ERR, "DRIVEMEM: Unknown drive type `%i'.", type);
    }
    return drive_ioreg_list;
}

mem_ioreg_list_t *drive0_ioreg_list_get(void)
{
    return drive_ioreg_list_get(drive0_context.drive_ptr->type);
}

mem_ioreg_list_t *drive1_ioreg_list_get(void)
{
    return drive_ioreg_list_get(drive1_context.drive_ptr->type);
}

