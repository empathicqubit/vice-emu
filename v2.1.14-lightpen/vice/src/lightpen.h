/*
 * lightpen.h - Lightpen/gun emulation
 *
 * Written by
 *  Hannu Nuotio <hannu.nuotio@tut.fi>
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

#ifndef VICE_LIGHTPEN_H
#define VICE_LIGHTPEN_H

#include "types.h"

extern int lightpen_resources_init(void);
extern int lightpen_cmdline_options_init(void);
extern void lightpen_init(void);

extern int lightpen_enabled;
extern int lightpen_type;
#define LIGHTPEN_TYPE_PEN   0
#define LIGHTPEN_TYPE_GUN   1

typedef CLOCK lightpen_timing_callback_t(int x, int y);
typedef lightpen_timing_callback_t *lightpen_timing_callback_ptr_t;
extern int lightpen_register_callback(lightpen_timing_callback_ptr_t timing_callback, int window);

extern void lightpen_update(int window, int x, int y, int buttons);
extern BYTE lightpen_read_button(void);

#endif
