/*
 * uivic20.c - Implementation of the VIC20-specific part of the UI.
 *
 * Written by
 *  Hannu Nuotio <hannu.nuotio@tut.fi>
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
#include <stdlib.h>

#include "ui.h"
#include "uimenu.h"
#include "vic20memrom.h"

static UI_MENU_CALLBACK(quit_callback)
{
    exit(0);
    return 0;
}

static ui_menu_entry_t xvic_main_menu[] = {
    { "Attach disk",
      MENU_ENTRY_SUBMENU,
      NULL, /* disk_attach_dialog */
      NULL,
      NULL },
    { "-", MENU_ENTRY_SEPARATOR, NULL, NULL, NULL },
    { "Quit",
      MENU_ENTRY_OTHER,
      quit_callback,
      NULL,
      NULL },
    { NULL }
};

BYTE vic20_font[8*256];

int vic20ui_init(void)
{
    int i, j;
fprintf(stderr,"%s\n",__func__);

    sdl_register_vcachename("VICVideoCache");
    sdl_ui_set_main_menu(xvic_main_menu);

    for (i=0; i<128; i++)
    {
        for (j=0; j<8; j++)
        {
            vic20_font[(i*8)+j]=vic20memrom_chargen_rom[(i*8)+(128*8)+j+0x800];
            vic20_font[(i*8)+(128*8)+j]=vic20memrom_chargen_rom[(i*8)+j+0x800];
        }
    }

    sdl_ui_set_menu_font(vic20_font, NULL, 0, 8, 8);
    return 0;
}

void vic20ui_shutdown(void)
{
fprintf(stderr,"%s\n",__func__);
}
