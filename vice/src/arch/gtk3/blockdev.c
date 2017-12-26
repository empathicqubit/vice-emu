/** \file   src/arch/gtk3/blockdev.c
 * \brief   Native GTK3 UI block device stuff.
 *
 * Written by
 *  Marco van den Heuvel <blackystardust68@yahoo.com>
 *  Bas Wassink <b.wassink@ziggo.nl>
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
#include <stdint.h>

#include "not_implemented.h"
#include "types.h"

#include "blockdev.h"


int blockdev_close(void)
{
#ifdef UNIX_COMPILE
    NOT_IMPLEMENTED();
    return 0;
#else
    /* windows */
    return -1;
#endif
}

int blockdev_cmdline_options_init(void)
{
    /* NOP, just like arch/unix */
    return 0;
}

void blockdev_init(void)
{
    /* NOP, just like arch/unix */
}

int blockdev_open(const char *name, unsigned int *read_only)
{
#ifdef UNIX_COMPILE
    NOT_IMPLEMENTED();
    return 0;
#else
    return -1;
#endif
}

int blockdev_read_sector(uint8_t *buf, unsigned int track, unsigned int sector)
{
#ifdef UNIX_COMPILE
    NOT_IMPLEMENTED();
    return 0;
#else
    return -1;
#endif
}

int blockdev_resources_init(void)
{
    /* NOP, just like arc/unix */
    return 0;
}

int blockdev_write_sector(const uint8_t *buf, unsigned int track, unsigned int sector)
{
#ifdef UNIX_COMPILE
    NOT_IMPLEMENTED();
    return 0;
#else
    return -1;
#endif
}

