/*
 * dqbb.h - DOUBLE QUICK BROWN BOX emulation.
 *
 * Written by
 *  Marco van den Heuvel <blackystardust68@yahoo.com>
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

#ifndef VICE_DQBB_H
#define VICE_DQBB_H

#include "types.h"

extern int dqbb_cart_enabled(void);

extern int dqbb_resources_init(void);
extern void dqbb_resources_shutdown(void);
extern int dqbb_cmdline_options_init(void);
extern void dqbb_reset(void);
extern void dqbb_detach(void);
extern void dqbb_init_config(void);
extern int dqbb_enable(void);
extern void dqbb_config_setup(BYTE *rawcart);

extern BYTE REGPARM1 dqbb_roml_read(WORD addr);
extern void REGPARM2 dqbb_roml_store(WORD addr, BYTE byte);
extern BYTE REGPARM1 dqbb_romh_read(WORD addr);
extern void REGPARM2 dqbb_romh_store(WORD addr, BYTE byte);

extern const char *dqbb_get_file_name(void);

#endif
