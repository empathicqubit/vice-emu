/*
 * traps.c - Allow VICE to replace ROM code with C function calls.
 *
 * Written by
 *  Teemu Rantanen <tvr@cs.hut.fi>
 *  Jarkko Sonninen <sonninen@lut.fi>
 *  Ettore Perazzoli <ettore@comm2000.it>
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

#include "cmdline.h"
#include "interrupt.h"
#include "lib.h"
#include "log.h"
#include "maincpu.h"
#include "mem.h"
#include "mos6510.h"
#include "parallel.h"
#include "resources.h"
#include "traps.h"
#include "types.h"


typedef struct traplist_s {
    struct traplist_s *next;
    const trap_t *trap;
} traplist_t;

static traplist_t *traplist = NULL;

static int install_trap(const trap_t *t);
static int remove_trap(const trap_t *t);

static log_t traps_log = LOG_ERR;

/* ------------------------------------------------------------------------- */

/* Trap-related resources.  */

/* Flag: Should we avoid installing traps at all?  */
static int traps_enabled;

static int set_traps_enabled(resource_value_t v, void *param)
{
    int new_value = (int)v;

    if ((!traps_enabled && new_value) || (traps_enabled && !new_value)) {
        if (!new_value) {
            /* Traps have been disabled.  */
            traplist_t *p;

            for (p = traplist; p != NULL; p = p->next)
                remove_trap(p->trap);
        } else {
            /* Traps have been enabled.  */
            traplist_t *p;

            for (p = traplist; p != NULL; p = p->next)
                install_trap(p->trap);
        }
    }

    traps_enabled = new_value;

    parallel_bus_enable(new_value);

    return 0;
}

static const resource_t resources[] = {
    { "VirtualDevices", RES_INTEGER, (resource_value_t)1,
      (void *)&traps_enabled, set_traps_enabled, NULL },
    { NULL }
};

int traps_resources_init(void)
{
    return resources_register(resources);
}

/* ------------------------------------------------------------------------- */

/* Trap-related command-line options.  */

static const cmdline_option_t cmdline_options[] = {
    { "-virtualdev", SET_RESOURCE, 0, NULL, NULL, "VirtualDevices",
        (resource_value_t)0,
      NULL, "Enable general mechanisms for fast disk/tape emulation" },
    { "+virtualdev", SET_RESOURCE, 0, NULL, NULL, "VirtualDevices",
        (resource_value_t)1,
      NULL, "Disable general mechanisms for fast disk/tape emulation" },
    { NULL }
};

int traps_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}

/* ------------------------------------------------------------------------- */

void traps_init(void)
{
    traps_log = log_open("Traps");
}

void traps_shutdown(void)
{
    traplist_t *list, *list_next;

    list = traplist;

    while (list != NULL) {
        list_next = list->next;
        lib_free(list);
        list = list_next;
    }
}

static int install_trap(const trap_t *t)
{
    int i;

    for (i = 0; i < 3; i++) {
        if ((t->readfunc)((WORD)(t->address + i)) != t->check[i]) {
            log_error(traps_log,
                      "Incorrect checkbyte for trap `%s'.  Not installed.",
                      t->name);
            return -1;
        }
    }

    /* BRK (0x00) is trap-opcode.  */
    (t->storefunc)(t->address, 0x00);

    return 0;
}

int traps_add(const trap_t *trap)
{
    traplist_t *p;

    p = (traplist_t *)lib_malloc(sizeof(traplist_t));
    p->next = traplist;
    p->trap = trap;
    traplist = p;

    if (traps_enabled)
        install_trap(trap);

    return 0;
}

static int remove_trap(const trap_t *trap)
{
    if ((trap->readfunc)(trap->address) != 0x00) {
        log_error(traps_log, "No trap `%s' installed?", trap->name);
        return -1;
    }

    (trap->storefunc)(trap->address, trap->check[0]);
    return 0;
}

int traps_remove(const trap_t *trap)
{
    traplist_t *p = traplist, *prev = NULL;

    while (p) {
        if (p->trap->address == trap->address)
            break;
        prev = p;
        p = p->next;
    }

    if (!p) {
        log_error(traps_log, "Trap `%s' not found.", trap->name);
        return -1;
    }

    if (prev)
        prev->next = p->next;
    else
        traplist = p->next;

    lib_free(p);

    if (traps_enabled)
        remove_trap(trap);

    return 0;
}

DWORD traps_handler(void)
{
    traplist_t *p = traplist;
    unsigned int pc = MOS6510_REGS_GET_PC(&maincpu_regs);
    int result;

    while (p) {
        if (p->trap->address == pc) {
            /* This allows the trap function to remove traps.  */
            WORD resume_address = p->trap->resume_address;

            result = (*p->trap->func)();
            if (!result) {
                return (p->trap->check[0] | (p->trap->check[1] << 8)
                    | (p->trap->check[2] << 16));
            } 
            /* XXX ALERT!  `p' might not be valid anymore here, because
               `p->trap->func()' might have removed all the traps.  */
            MOS6510_REGS_SET_PC(&maincpu_regs, resume_address);
            return 0;
        }
        p = p->next;
    }

    return -1;
}

