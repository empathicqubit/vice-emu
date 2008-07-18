/*
 * uigeoram.c - GEORAM UI interface for MS-DOS.
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

#include <stdio.h>

#include "resources.h"
#include "tui.h"
#include "tuimenu.h"
#include "uigeoram.h"


TUI_MENU_DEFINE_TOGGLE(GEORAM)
TUI_MENU_DEFINE_RADIO(GEORAMsize)


static TUI_MENU_CALLBACK(georam_size_submenu_callback)
{
    int value;
    static char s[100];

    resources_get_int("GEORAMsize", &value);
    sprintf(s, "%dKB",value);
    return s;
}

static tui_menu_item_def_t georam_size_submenu[] = {
    { "_64KB", NULL, radio_GEORAMsize_callback,
      (void *)64, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { "_128KB", NULL, radio_GEORAMsize_callback,
      (void *)128, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { "_256KB", NULL, radio_GEORAMsize_callback,
      (void *)256, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { "_512KB", NULL, radio_GEORAMsize_callback,
      (void *)512, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { "102_4KB", NULL, radio_GEORAMsize_callback,
      (void *)1024, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { "2_048KB", NULL, radio_GEORAMsize_callback,
      (void *)2048, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { "40_96KB", NULL, radio_GEORAMsize_callback,
      (void *)4096, 7, TUI_MENU_BEH_CLOSE, NULL, NULL },
    { NULL }
};

static TUI_MENU_CALLBACK(georam_image_file_callback)
{
    char s[256];
    const char *v;

    if (been_activated) {

        *s = '\0';

        if (tui_input_string("Change GEORAM image name",
                             "New image name:", s, 255) == -1)
            return NULL;

        if (*s == '\0')
            return NULL;

        resources_set_string("GEORAMfilename", s);
    }

    resources_get_string("GEORAMfilename", &v);

    return v;
}

static tui_menu_item_def_t georam_menu_items[] = {
    { "_Enable GEORAM:", "Emulate GEORAM Expansion Unit",
      toggle_GEORAM_callback, NULL, 3,
      TUI_MENU_BEH_CONTINUE, NULL, NULL },
    { "GEORAM _size:", "Select the size of the GEORAM",
      georam_size_submenu_callback, NULL, 7,
      TUI_MENU_BEH_CONTINUE, georam_size_submenu,
      "GEORAM size" },
    { "GEORAM _image file:", "Select the GEORAM image file",
      georam_image_file_callback, NULL, 20,
      TUI_MENU_BEH_CONTINUE, NULL, NULL },
    { NULL }
};

void uigeoram_init(struct tui_menu *parent_submenu)
{
    tui_menu_t ui_georam_submenu;

    ui_georam_submenu = tui_menu_create("GEORAM settings", 1);

    tui_menu_add(ui_georam_submenu, georam_menu_items);

    tui_menu_add_submenu(parent_submenu, "_GEORAM settings...",
                         "GEORAM settings",
                         ui_georam_submenu, NULL, 0,
                         TUI_MENU_BEH_CONTINUE);
}

