/*! \file monitor_binary.h \n
 *  \author Spiro Trikaliotis
 *  \brief   Monitor implementation - binary access
 *
 * monitor_binary.h - Monitor implementation - binary access.
 *
 * Written by
 *  Spiro Trikaliotis <spiro.trikaliotis@gmx.de>
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


#ifndef VICE_MONITOR_BINARY_H
#define VICE_MONITOR_BINARY_H

#include "types.h"
#include "uiapi.h"

extern int monitor_binary_resources_init(void);
extern void monitor_binary_resources_shutdown(void);
extern int monitor_binary_cmdline_options_init(void);

extern void monitor_check_binary(void);

extern int monitor_binary_receive(char * buffer, size_t buffer_length);
extern int monitor_binary_transmit(const char * buffer, size_t buffer_length);
extern int monitor_binary_get_command_line(void);

extern int monitor_is_binary(void);

extern ui_jam_action_t monitor_binary_ui_jam_dialog(const char *format, ...);

#endif