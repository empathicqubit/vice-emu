/*
 * menu_c64dtvhw.c - C64DTV HW menu for SDL UI.
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

#include "vice.h"
#include "types.h"

#include "c64dtv-resources.h"
#include "menu_common.h"
#include "menu_joystick.h"
#include "menu_ram.h"
#include "menu_rom.h"
#include "menu_sid.h"
#include "uimenu.h"

UI_MENU_DEFINE_RADIO(HummerUserportDevice)
UI_MENU_DEFINE_RADIO(HummerUserportJoyPort)
#ifdef HAVE_MOUSE
UI_MENU_DEFINE_TOGGLE(ps2mouse)
UI_MENU_DEFINE_TOGGLE(Mouse)
#endif

static const ui_menu_entry_t c64dtv_userport_menu[] = {
    SDL_MENU_ITEM_TITLE("Hummer userport device"),
    { "None",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_HummerUserportDevice_callback,
      (ui_callback_data_t)HUMMER_USERPORT_NONE },
    { "ADC",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_HummerUserportDevice_callback,
      (ui_callback_data_t)HUMMER_USERPORT_ADC },
    { "Joystick",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_HummerUserportDevice_callback,
      (ui_callback_data_t)HUMMER_USERPORT_JOY },
    SDL_MENU_ITEM_SEPARATOR,
    SDL_MENU_ITEM_TITLE("Hummer joystick port mapped to userport"),
    { "Joy1",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_HummerUserportJoyPort_callback,
      (ui_callback_data_t)1 },
    { "Joy2",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_HummerUserportJoyPort_callback,
      (ui_callback_data_t)2 },
#ifdef HAVE_MOUSE
    SDL_MENU_ITEM_SEPARATOR,
    SDL_MENU_ITEM_TITLE("PS/2 mouse on userport"),
    { "Enable PS/2 mouse",
      MENU_ENTRY_RESOURCE_TOGGLE,
      toggle_ps2mouse_callback,
      NULL },
    { "Grab mouse events",
      MENU_ENTRY_RESOURCE_TOGGLE,
      toggle_Mouse_callback,
      NULL },
#endif
};

UI_MENU_DEFINE_FILE_STRING(c64dtvromfilename)
UI_MENU_DEFINE_TOGGLE(c64dtvromrw)
UI_MENU_DEFINE_TOGGLE(FlashTrueFS)
UI_MENU_DEFINE_RADIO(DtvRevision)

const ui_menu_entry_t c64dtv_hardware_menu[] = {
    { "Joystick settings",
      MENU_ENTRY_SUBMENU,
      submenu_callback,
      (ui_callback_data_t)joystick_menu },
    { "SID settings",
      MENU_ENTRY_SUBMENU,
      submenu_callback,
      (ui_callback_data_t)sid_dtv_menu },
    { "RAM pattern settings",
      MENU_ENTRY_SUBMENU,
      submenu_callback,
      (ui_callback_data_t)ram_menu },
    { "Fallback ROM settings",
      MENU_ENTRY_SUBMENU,
      submenu_callback,
      (ui_callback_data_t)c64dtv_rom_menu },
    SDL_MENU_ITEM_SEPARATOR,
    SDL_MENU_ITEM_TITLE("C64DTV ROM image"),
    { "File",
      MENU_ENTRY_DIALOG,
      file_string_c64dtvromfilename_callback,
      (ui_callback_data_t)"Select C64DTV ROM image file" },
    { "Enable writes",
      MENU_ENTRY_RESOURCE_TOGGLE,
      toggle_c64dtvromrw_callback,
      NULL },
    { "True flash filesystem",
      MENU_ENTRY_RESOURCE_TOGGLE,
      toggle_FlashTrueFS_callback,
      NULL },
    SDL_MENU_ITEM_SEPARATOR,
    SDL_MENU_ITEM_TITLE("DTV revision"),
    { "DTV2",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_DtvRevision_callback,
      (ui_callback_data_t)2 },
    { "DTV3",
      MENU_ENTRY_RESOURCE_RADIO,
      radio_DtvRevision_callback,
      (ui_callback_data_t)3 },
    SDL_MENU_ITEM_SEPARATOR,
    { "Userport settings",
      MENU_ENTRY_SUBMENU,
      submenu_callback,
      (ui_callback_data_t)c64dtv_userport_menu },
    { NULL }
};
