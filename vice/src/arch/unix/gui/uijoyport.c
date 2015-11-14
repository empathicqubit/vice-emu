/*
 * uijoyport.c - Implementation of joyport UI settings.
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

#include "lib.h"
#include "joyport.h"
#include "translate.h"
#include "uilib.h"
#include "uimenu.h"
#include "uijoyport.h"

UI_MENU_DEFINE_RADIO(JoyPort1Device)
UI_MENU_DEFINE_RADIO(JoyPort2Device)
UI_MENU_DEFINE_RADIO(JoyPort3Device)

ui_menu_entry_t joyport1_settings_submenu[] = {
    { N_("Control port device"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, NULL },
    { NULL },
};

ui_menu_entry_t joyport2_settings_submenu[] = {
    { N_("Control port 1 device"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, NULL },
    { N_("Control port 2 device"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, NULL },
    { NULL },
};

ui_menu_entry_t joyport3_settings_submenu[] = {
    { N_("Control port 1 device"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, NULL },
    { N_("Control port 2 device"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, NULL },
    { N_("SIDCard control port device"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, NULL },
    { NULL },
};

ui_menu_entry_t ui_joyport1_settings_menu[] = {
    { N_("Control port settings"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, joyport1_settings_submenu },
    { NULL }
};

ui_menu_entry_t ui_joyport2_settings_menu[] = {
    { N_("Control port settings"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, joyport2_settings_submenu },
    { NULL }
};

ui_menu_entry_t ui_joyport3_settings_menu[] = {
    { N_("Control port settings"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, joyport3_settings_submenu },
    { NULL }
};

void uijoyport_menu_create(int ports)
{
    unsigned int i, num;
    ui_menu_entry_t *devices_submenu1;
    ui_menu_entry_t *devices_submenu2;
    ui_menu_entry_t *devices_submenu3;
    joyport_desc_t *devices_port_1 = joyport_get_valid_devices(JOYPORT_1);
    joyport_desc_t *devices_port_2 = joyport_get_valid_devices(JOYPORT_2);
    joyport_desc_t *devices_port_3 = joyport_get_valid_devices(JOYPORT_3);

    for (i = 0; devices_port_1[i].name; ++i) {}
    num = i;

    if (!num) {
        return;
    }

    devices_submenu1 = lib_calloc((size_t)(num + 1), sizeof(ui_menu_entry_t));

    for (i = 0; i < num ; i++) {
        devices_submenu1[i].string = (ui_callback_data_t)lib_msprintf("%s", translate_text(devices_port_1[i].trans_name));
        devices_submenu1[i].type = UI_MENU_TYPE_TICK;
        devices_submenu1[i].callback = (ui_callback_t)radio_JoyPort1Device;
        devices_submenu1[i].callback_data = (ui_callback_data_t)(unsigned long)devices_port_1[i].id;
    }

    if (ports > 1) {
        for (i = 0; devices_port_2[i].name; ++i) {}
        num = i;

        if (!num) {
            return;
        }
        devices_submenu2 = lib_calloc((size_t)(num + 1), sizeof(ui_menu_entry_t));
        for (i = 0; i < num ; i++) {
            devices_submenu2[i].string = (ui_callback_data_t)lib_msprintf("%s", translate_text(devices_port_2[i].trans_name));
            devices_submenu2[i].type = UI_MENU_TYPE_TICK;
            devices_submenu2[i].callback = (ui_callback_t)radio_JoyPort2Device;
            devices_submenu2[i].callback_data = (ui_callback_data_t)(unsigned long)devices_port_2[i].id;
        }
    }

    if (ports > 2) {
        for (i = 0; devices_port_3[i].name; ++i) {}
        num = i;

        if (!num) {
            return;
        }
        devices_submenu3 = lib_calloc((size_t)(num + 1), sizeof(ui_menu_entry_t));
        for (i = 0; i < num ; i++) {
            devices_submenu3[i].string = (ui_callback_data_t)lib_msprintf("%s", translate_text(devices_port_3[i].trans_name));
            devices_submenu3[i].type = UI_MENU_TYPE_TICK;
            devices_submenu3[i].callback = (ui_callback_t)radio_JoyPort3Device;
            devices_submenu3[i].callback_data = (ui_callback_data_t)(unsigned long)devices_port_3[i].id;
        }
    }

    switch (ports) {
        case 1:
            joyport1_settings_submenu[0].sub_menu = devices_submenu1;
            break;
        case 2:
            joyport2_settings_submenu[0].sub_menu = devices_submenu1;
            joyport2_settings_submenu[1].sub_menu = devices_submenu2;
            break;
        case 3:
            joyport3_settings_submenu[0].sub_menu = devices_submenu1;
            joyport3_settings_submenu[1].sub_menu = devices_submenu2;
            joyport3_settings_submenu[2].sub_menu = devices_submenu3;
            break;
    }
    lib_free(devices_port_1);
    lib_free(devices_port_2);
    lib_free(devices_port_3);
}

void uijoyport_menu_shutdown(int ports)
{
    unsigned int i;
    ui_menu_entry_t *devices_submenu1 = NULL;
    ui_menu_entry_t *devices_submenu2 = NULL;
    ui_menu_entry_t *devices_submenu3 = NULL;

    switch (ports) {
        case 3:
            devices_submenu1 = joyport3_settings_submenu[0].sub_menu;
            joyport3_settings_submenu[0].sub_menu = NULL;
            devices_submenu2 = joyport3_settings_submenu[1].sub_menu;
            joyport3_settings_submenu[1].sub_menu = NULL;
            devices_submenu3 = joyport3_settings_submenu[2].sub_menu;
            joyport3_settings_submenu[2].sub_menu = NULL;
            break;
        case 2:
            devices_submenu1 = joyport2_settings_submenu[0].sub_menu;
            joyport2_settings_submenu[0].sub_menu = NULL;
            devices_submenu2 = joyport2_settings_submenu[1].sub_menu;
            joyport2_settings_submenu[1].sub_menu = NULL;
            break;
        case 1:
            devices_submenu1 = joyport1_settings_submenu[0].sub_menu;
            joyport1_settings_submenu[0].sub_menu = NULL;
            break;
    }

    i = 0;
    while (devices_submenu1[i].string != NULL) {
        lib_free(devices_submenu1[i].string);
        i++;
    }
    lib_free(devices_submenu1);

    if (ports > 1) {
        i = 0;
        while (devices_submenu2[i].string != NULL) {
            lib_free(devices_submenu2[i].string);
            i++;
        }
        lib_free(devices_submenu2);
    }

    if (ports > 2) {
        i = 0;
        while (devices_submenu3[i].string != NULL) {
            lib_free(devices_submenu3[i].string);
            i++;
        }
        lib_free(devices_submenu3);
    }
}