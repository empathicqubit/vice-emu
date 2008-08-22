/*
 * joy.h - Joystick support for Linux.
 *
 * Written by
 *  Hannu Nuotio <hannu.nuotio@tut.fi>
 *
 * Based on code by
 *  Bernhard Kuhn <kuhn@eikon.e-technik.tu-muenchen.de>
 *  Ulmer Lionel <ulmer@poly.polytechnique.fr>
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

#ifndef _JOY_H
#define _JOY_H

#include <SDL/SDL.h>

extern int joy_arch_init(void);
extern void joystick_close(void);
extern int joystick_arch_init_resources(void);
extern int joystick_init_cmdline_options(void);
extern void joy_arch_init_default_mapping(int joynum);
extern void sdljoy_axis_event(Uint8 joynum, Uint8 axis, Sint16 value);
extern void sdljoy_button_event(Uint8 joynum, Uint8 button, Uint8 value);

extern int joystick_port_map[2];

#define JOYDEV_NONE         0
#define JOYDEV_NUMPAD       1
#define JOYDEV_KEYSET1      2
#define JOYDEV_KEYSET2      3
#define JOYDEV_JOYSTICK     4

#endif

