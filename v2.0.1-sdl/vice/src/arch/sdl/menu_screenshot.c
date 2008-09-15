/*
 * menu_screenshot.c - SDL screenshot saving functions.
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

#include "vice.h"
#include "types.h"

#include <stdlib.h>

#include "lib.h"
#include "menu_common.h"
#include "menu_screenshot.h"
#include "resources.h"
#include "screenshot.h"
#include "ui.h"
#include "uifilereq.h"
#include "uimenu.h"
#include "videoarch.h"

static UI_MENU_CALLBACK(save_screenshot_callback)
{
    char title[20];
    char *name = NULL;

    if (activated) {
        sprintf(title, "Choose %s file", (char *)param);
        name = sdl_ui_file_selection_dialog(title, FILEREQ_MODE_CHOOSE_FILE);
        if (name != NULL) {
            if (screenshot_save((char *)param, name, sdl_active_canvas) < 0) {
                ui_error("Cannot save screenshot.");
            } else {
                ui_message("Screenshot saved.");
            }
            lib_free(name);
        }
    }
    return NULL;
}

const ui_menu_entry_t screenshot_menu[] = {
    { "Save BMP screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"BMP" },
#ifdef HAVE_GIF
    { "Save GIF screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"GIF" },
#endif
    { "Save IFF screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"IFF" },
#ifdef HAVE_JPEG
    { "Save JPG screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"JPG" },
#endif
    { "Save PCX screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"PCX" },
#ifdef HAVE_PNG
    { "Save PNG screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"PNG" },
#endif
    { "Save PPM screenshot",
      MENU_ENTRY_OTHER,
      save_screenshot_callback,
      (ui_callback_data_t)"PPM" },
    { NULL }
};
