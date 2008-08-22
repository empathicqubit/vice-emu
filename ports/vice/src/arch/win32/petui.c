/*
 * petui.c - PET-specific user interface.
 *
 * Written by
 *  Andreas Boose <viceteam@t-online.de>
 *  Ettore Perazzoli <ettore@comm2000.it>
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
#include <windows.h>

#include "petui.h"
#include "res.h"
#include "translate.h"
#include "ui.h"
#include "uiacia.h"
#include "uidrivepetcbm2.h"
#include "uikeyboard.h"
#include "uipetreu.h"
#include "uipetset.h"
#include "uirom.h"
#include "uisidcart.h"
#include "uivideo.h"
#include "winmain.h"

static const unsigned int romset_dialog_resources[UIROM_TYPE_MAX] = {
    IDD_PETROM_RESOURCE_DIALOG,
    IDD_PETROMDRIVE_RESOURCE_DIALOG,
    0 };


static const ui_menu_toggle_t pet_ui_menu_toggles[] = {
    { "EmuID", IDM_TOGGLE_EMUID },
    { "CrtcDoubleSize", IDM_TOGGLE_CRTCDOUBLESIZE },
    { "CrtcDoubleScan", IDM_TOGGLE_CRTCDOUBLESCAN },
    { "CrtcVideoCache", IDM_TOGGLE_CRTCVIDEOCACHE },
    { NULL, 0 }
};

static const uirom_settings_t uirom_settings[] = {
    { UIROM_TYPE_MAIN, TEXT("Kernal"), "KernalName",
      IDC_PETROM_KERNAL_FILE, IDC_PETROM_KERNAL_BROWSE,
      IDC_PETROM_KERNAL_RESOURCE },
    { UIROM_TYPE_MAIN, TEXT("Basic"), "BasicName",
      IDC_PETROM_BASIC_FILE, IDC_PETROM_BASIC_BROWSE,
      IDC_PETROM_BASIC_RESOURCE },
    { UIROM_TYPE_MAIN, TEXT("Character"), "ChargenName",
      IDC_PETROM_CHARGEN_FILE, IDC_PETROM_CHARGEN_BROWSE,
      IDC_PETROM_CHARGEN_RESOURCE },
    { UIROM_TYPE_MAIN, TEXT("Editor"), "EditorName",
      IDC_PETROM_EDITOR_FILE, IDC_PETROM_EDITOR_BROWSE,
      IDC_PETROM_EDITOR_RESOURCE },
    { UIROM_TYPE_MAIN, TEXT("ROM9"), "RomModule9Name",
      IDC_PETROM_ROM9_FILE, IDC_PETROM_ROM9_BROWSE,
      IDC_PETROM_ROM9_RESOURCE },
    { UIROM_TYPE_MAIN, TEXT("ROMA"), "RomModuleAName",
      IDC_PETROM_ROMA_FILE, IDC_PETROM_ROMA_BROWSE,
      IDC_PETROM_ROMA_RESOURCE },
    { UIROM_TYPE_MAIN, TEXT("ROMB"), "RomModuleBName",
      IDC_PETROM_ROMB_FILE, IDC_PETROM_ROMB_BROWSE,
      IDC_PETROM_ROMB_RESOURCE },
    { UIROM_TYPE_DRIVE, TEXT("2031"), "DosName2031",
      IDC_DRIVEROM_2031_FILE, IDC_DRIVEROM_2031_BROWSE,
      IDC_DRIVEROM_2031_RESOURCE },
    { UIROM_TYPE_DRIVE, TEXT("2040"), "DosName2040",
      IDC_DRIVEROM_2040_FILE, IDC_DRIVEROM_2040_BROWSE,
      IDC_DRIVEROM_2040_RESOURCE },
    { UIROM_TYPE_DRIVE, TEXT("3040"), "DosName3040",
      IDC_DRIVEROM_3040_FILE, IDC_DRIVEROM_3040_BROWSE,
      IDC_DRIVEROM_3040_RESOURCE },
    { UIROM_TYPE_DRIVE, TEXT("4040"), "DosName4040",
      IDC_DRIVEROM_4040_FILE, IDC_DRIVEROM_4040_BROWSE,
      IDC_DRIVEROM_4040_RESOURCE },
    { UIROM_TYPE_DRIVE, TEXT("1001"), "DosName1001",
      IDC_DRIVEROM_1001_FILE, IDC_DRIVEROM_1001_BROWSE,
      IDC_DRIVEROM_1001_RESOURCE },
    { 0, NULL, NULL, 0, 0, 0 }
};

#define PETUI_KBD_NUM_MAP 6

static const uikeyboard_mapping_entry_t mapping_entry[PETUI_KBD_NUM_MAP] = {
    { IDC_PETKBD_MAPPING_SELECT_UKSYM, IDC_PETKBD_MAPPING_UKSYM,
      IDC_PETKBD_MAPPING_UKSYM_BROWSE, "KeymapBusinessUKSymFile" },
    { IDC_PETKBD_MAPPING_SELECT_UKPOS, IDC_PETKBD_MAPPING_UKPOS,
      IDC_PETKBD_MAPPING_UKPOS_BROWSE, "KeymapBusinessUKPosFile" },
    { IDC_PETKBD_MAPPING_SELECT_GRSYM, IDC_PETKBD_MAPPING_GRSYM,
      IDC_PETKBD_MAPPING_GRSYM_BROWSE, "KeymapGraphicsSymFile" },
    { IDC_PETKBD_MAPPING_SELECT_GRPOS, IDC_PETKBD_MAPPING_GRPOS,
      IDC_PETKBD_MAPPING_GRPOS_BROWSE, "KeymapGraphicsPosFile" },
    { IDC_PETKBD_MAPPING_SELECT_DESYM, IDC_PETKBD_MAPPING_DESYM,
      IDC_PETKBD_MAPPING_DESYM_BROWSE, "KeymapBusinessDESymFile" },
    { IDC_PETKBD_MAPPING_SELECT_DEPOS, IDC_PETKBD_MAPPING_DEPOS,
      IDC_PETKBD_MAPPING_DEPOS_BROWSE, "KeymapBusinessDEPosFile" }
};

static uikeyboard_config_t uikeyboard_config =
    { IDD_PETKBD_MAPPING_SETTINGS_DIALOG, PETUI_KBD_NUM_MAP, mapping_entry,
      IDC_PETKBD_MAPPING_DUMP };

ui_menu_translation_table_t petui_menu_translation_table[] = {
    { IDM_EXIT, IDS_MI_EXIT },
    { IDM_ABOUT, IDS_MI_ABOUT },
    { IDM_PAUSE, IDS_MI_PAUSE },
    { IDM_EDIT_COPY, IDS_MI_EDIT_COPY },
    { IDM_EDIT_PASTE, IDS_MI_EDIT_PASTE },
    { IDM_AUTOSTART, IDS_MI_AUTOSTART },
    { IDM_RESET_HARD, IDS_MI_RESET_HARD },
    { IDM_RESET_SOFT, IDS_MI_RESET_SOFT },
    { IDM_RESET_DRIVE8, IDS_MI_DRIVE8 },
    { IDM_RESET_DRIVE9, IDS_MI_DRIVE9 },
    { IDM_RESET_DRIVE10, IDS_MI_DRIVE10 },
    { IDM_RESET_DRIVE11, IDS_MI_DRIVE11 },
    { IDM_ATTACH_8, IDS_MI_DRIVE8 },
    { IDM_ATTACH_9, IDS_MI_DRIVE9 },
    { IDM_ATTACH_10, IDS_MI_DRIVE10 },
    { IDM_ATTACH_11, IDS_MI_DRIVE11 },
    { IDM_DETACH_8, IDS_MI_DRIVE8 },
    { IDM_DETACH_9, IDS_MI_DRIVE9 },
    { IDM_DETACH_10, IDS_MI_DRIVE10 },
    { IDM_DETACH_11, IDS_MI_DRIVE11 },
    { IDM_ATTACH_TAPE, IDS_MI_ATTACH_TAPE },
    { IDM_DETACH_TAPE, IDS_MI_DETACH_TAPE },
    { IDM_DETACH_ALL, IDS_MI_DETACH_ALL },
    { 0, 0 }
};

ui_popup_translation_table_t petui_popup_translation_table[] = {
    { 1, IDS_MP_FILE },
    { 2, IDS_MP_ATTACH_DISK_IMAGE },
    { 2, IDS_MP_DETACH_DISK_IMAGE },
    { 2, IDS_MP_FLIP_LIST },
    { 2, IDS_MP_DATASETTE_CONTROL },
    { 2, IDS_MP_RESET },
#ifdef DEBUG
    { 2, IDS_MP_DEBUG },
    { 3, IDS_MP_MODE },
#endif
    { 1, IDS_MP_EDIT },
    { 1, IDS_MP_SNAPSHOT },
    { 2, IDS_MP_RECORDING_START_MODE },
    { 1, IDS_MP_OPTIONS },
    { 2, IDS_MP_REFRESH_RATE },
    { 2, IDS_MP_MAXIMUM_SPEED },
    { 2, IDS_MP_DRIVE_SYNC_FACTOR },
    { 1, IDS_MP_SETTINGS },
    { 2, IDS_MP_CARTRIDGE_IO_SETTINGS },
    { 1, IDS_MP_LANGUAGE },
    { 1, IDS_MP_HELP },
    { 0, 0 }
};

static void pet_ui_specific(WPARAM wparam, HWND hwnd)
{
    switch (wparam) {
      case IDM_PET_SETTINGS:
        ui_pet_settings_dialog(hwnd);
        break;
      case IDM_PETREU_SETTINGS:
        ui_petreu_settings_dialog(hwnd);
        break;
      case IDM_SIDCART_SETTINGS:
        ui_sidcart_settings_dialog(hwnd);
        break;
      case IDM_ROM_SETTINGS:
        uirom_settings_dialog(hwnd, translate_res(IDD_PETROM_SETTINGS_DIALOG),
                              translate_res(IDD_PETDRIVEROM_SETTINGS_DIALOG),
                              romset_dialog_resources, uirom_settings);
        break;
      case IDM_VIDEO_SETTINGS:
        ui_video_settings_dialog(hwnd, UI_VIDEO_CHIP_CRTC, UI_VIDEO_CHIP_NONE);
        break;
      case IDM_DRIVE_SETTINGS:
        uidrivepetcbm2_settings_dialog(hwnd);
        break;
      case IDM_ACIA_SETTINGS:
        ui_acia_settings_dialog(hwnd, 0, NULL, 0, 0);
        break;
      case IDM_KEYBOARD_SETTINGS:
        uikeyboard_settings_dialog(hwnd, &uikeyboard_config);
        break;
    }
}

int petui_init(void)
{
    ui_register_machine_specific(pet_ui_specific);
    ui_register_menu_toggles(pet_ui_menu_toggles);
    ui_register_translation_tables(petui_menu_translation_table, petui_popup_translation_table);
    return 0;
}

void petui_shutdown(void)
{
}

