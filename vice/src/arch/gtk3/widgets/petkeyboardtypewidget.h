/** \file   src/arch/gtk3/widgets/petkeyboardtypewidget.h
 * \brief   PET keyboard type widget - header
 *
 * Written by
 *  Bas Wassink <b.wassink@ziggo.nl>
 *   MachineType
 *
 * Controls the following resource(s):
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

#ifndef HAVE_PETKEYBOARDTYPEWIDGET_H
#define HAVE_PETKEYBOARDTYPEWIDGET_H

#include "vice.h"
#include <gtk/gtk.h>
#include "machine.h"

void pet_keyboard_type_widget_set_keyboard_num_get(int (*f)(void));
void pet_keyboard_type_widget_set_keyboard_list_get(kbdtype_info_t *(*f)(void));

GtkWidget * pet_keyboard_type_widget_create(void);

#endif