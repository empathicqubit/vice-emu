/*
 * uimmcreplay.c
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

#include "uilib.h"
#include "uimenu.h"
#include "uimmcreplay.h"


UI_MENU_DEFINE_TOGGLE(MMCRCardRW)
UI_MENU_DEFINE_TOGGLE(MMCREEPROMRW)
UI_MENU_DEFINE_TOGGLE(MMCRRescueMode)
UI_MENU_DEFINE_RADIO(MMCRSDType)

UI_CALLBACK(set_mmcreplay_card_filename)
{
    uilib_select_file((char *)UI_MENU_CB_PARAM, _("MMC Replay card image filename"),
                        UILIB_FILTER_ALL);
}

UI_CALLBACK(set_mmcreplay_eeprom_filename)
{
#ifdef USE_GNOMEUI
    uilib_select_file((char *)UI_MENU_CB_PARAM, _("MMC Replay EEPROM image filename"),
                        UILIB_FILTER_ALL);
#else
    /* XAW ui does not allow to enter non existing file in file browser */
    uilib_select_string((char *)UI_MENU_CB_PARAM, _("MMC Replay EEPROM image filename"),
                        _("Image:"));
#endif
}

static ui_menu_entry_t mmcreplay_sd_type_submenu[] = {
    { N_("Auto"), UI_MENU_TYPE_TICK, (ui_callback_t)radio_MMCRSDType,
      (ui_callback_data_t)0, NULL },
    { "MMC", UI_MENU_TYPE_TICK, (ui_callback_t)radio_MMCRSDType,
      (ui_callback_data_t)1, NULL },
    { "SD", UI_MENU_TYPE_TICK, (ui_callback_t)radio_MMCRSDType,
      (ui_callback_data_t)2, NULL },
    { "SDHC", UI_MENU_TYPE_TICK, (ui_callback_t)radio_MMCRSDType,
      (ui_callback_data_t)3, NULL },
    { NULL }
};


ui_menu_entry_t mmcreplay_submenu[] = {
    { N_("Card image filename..."), UI_MENU_TYPE_NORMAL,
      (ui_callback_t)set_mmcreplay_card_filename,
      (ui_callback_data_t)"MMCRCardImage", NULL },
    { N_("Enable writes to card image"), UI_MENU_TYPE_TICK,
      (ui_callback_t)toggle_MMCRCardRW, NULL, NULL },
    { N_("EEPROM image filename..."), UI_MENU_TYPE_NORMAL,
      (ui_callback_t)set_mmcreplay_eeprom_filename,
      (ui_callback_data_t)"MMCREEPROMImage", NULL },
    { N_("Enable writes to EEPROM image"), UI_MENU_TYPE_TICK,
      (ui_callback_t)toggle_MMCREEPROMRW, NULL, NULL },
    { N_("Enable rescue mode"), UI_MENU_TYPE_TICK,
      (ui_callback_t)toggle_MMCRRescueMode, NULL, NULL },
    { N_("Card Type"), UI_MENU_TYPE_NORMAL,
      NULL, NULL, mmcreplay_sd_type_submenu },
    { NULL }
};
