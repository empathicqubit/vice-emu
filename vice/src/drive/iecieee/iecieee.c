/*
 * iecieee.c
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

#include "drive.h"
#include "drivetypes.h"
#include "iecieee.h"
#include "types.h"
#include "viad.h"


void iecieee_drive_init(struct drive_context_s *drv)
{
    via1d_init(drv);
    via2d_init(drv);
}

void iecieee_drive_reset(struct drive_context_s *drv)
{
    via1d_reset(drv);
    via2d_reset(drv);
}

void iecieee_drive_setup_context(struct drive_context_s *drv)
{
    via1d_setup_context(drv);
    via2d_setup_context(drv);
}

int iecieee_drive_snapshot_read(struct drive_context_s *ctxptr,
                                struct snapshot_s *s)
{
    if (ctxptr->drive_ptr->type == DRIVE_TYPE_1541
        || ctxptr->drive_ptr->type == DRIVE_TYPE_1541II
        || ctxptr->drive_ptr->type == DRIVE_TYPE_1571
        || ctxptr->drive_ptr->type == DRIVE_TYPE_2031) {
        if (via1d_snapshot_read_module(ctxptr, s) < 0
            || via2d_snapshot_read_module(ctxptr, s) < 0)
            return -1;
    }

    return 0;
}

int iecieee_drive_snapshot_write(struct drive_context_s *ctxptr,
                                 struct snapshot_s *s)
{
    if (ctxptr->drive_ptr->type == DRIVE_TYPE_1541
        || ctxptr->drive_ptr->type == DRIVE_TYPE_1541II
        || ctxptr->drive_ptr->type == DRIVE_TYPE_1571
        || ctxptr->drive_ptr->type == DRIVE_TYPE_2031) {
        if (via1d_snapshot_write_module(ctxptr, s) < 0
            || via2d_snapshot_write_module(ctxptr, s) < 0)
            return -1;
    }

    return 0;
}

