/*
 * uiide64.c
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
#ifdef AMIGA_M68K
#define _INLINE_MUIMASTER_H
#endif
#include "mui.h"

#include "uiide64.h"
#include "intl.h"
#include "translate.h"

static video_canvas_t *ide64_canvas;

static int ui_ide64_autodetect_translate[] = {
    IDMS_DISABLED,
    IDS_ENABLED,
    0
};

static char *ui_ide64_autodetect[countof(ui_ide64_autodetect_translate)];

static const int ui_ide64_autodetect_values[] = {
    0,
    1,
    -1
};

static ui_to_from_t ui_to_from[] = {
    { NULL, MUI_TYPE_FILENAME, "IDE64Image1", NULL, NULL, NULL },
    { NULL, MUI_TYPE_FILENAME, "IDE64Image2", NULL, NULL, NULL },
    { NULL, MUI_TYPE_FILENAME, "IDE64Image3", NULL, NULL, NULL },
    { NULL, MUI_TYPE_FILENAME, "IDE64Image4", NULL, NULL, NULL },
    { NULL, MUI_TYPE_CYCLE, "IDE64version4", ui_ide64_autodetect, ui_ide64_autodetect_values, NULL },
    { NULL, MUI_TYPE_CYCLE, "IDE64AutodetectSize", ui_ide64_autodetect, ui_ide64_autodetect_values, NULL },
    { NULL, MUI_TYPE_INTEGER, "IDE64Cylinders", NULL, NULL, NULL },
    { NULL, MUI_TYPE_INTEGER, "IDE64Heads", NULL, NULL, NULL },
    { NULL, MUI_TYPE_INTEGER, "IDE64Sectors", NULL, NULL, NULL },
    UI_END /* mandatory */
};

static ULONG Browse1( struct Hook *hook, Object *obj, APTR arg )
{
    char *fname = NULL;

    fname = BrowseFile(translate_text(IDS_IDE64_FILENAME_SELECT), "#?", ide64_canvas);

    if (fname != NULL) {
        set(ui_to_from[0].object, MUIA_String_Contents, fname);
    }

    return 0;
}

static ULONG Browse2( struct Hook *hook, Object *obj, APTR arg )
{
    char *fname = NULL;

    fname = BrowseFile(translate_text(IDS_IDE64_FILENAME_SELECT), "#?", ide64_canvas);

    if (fname != NULL) {
        set(ui_to_from[1].object, MUIA_String_Contents, fname);
    }

    return 0;
}

static ULONG Browse3( struct Hook *hook, Object *obj, APTR arg )
{
    char *fname = NULL;

    fname = BrowseFile(translate_text(IDS_IDE64_FILENAME_SELECT), "#?", ide64_canvas);

    if (fname != NULL) {
        set(ui_to_from[2].object, MUIA_String_Contents, fname);
    }

    return 0;
}

static ULONG Browse4( struct Hook *hook, Object *obj, APTR arg )
{
    char *fname = NULL;

    fname = BrowseFile(translate_text(IDS_IDE64_FILENAME_SELECT), "#?", ide64_canvas);

    if (fname != NULL) {
        set(ui_to_from[3].object, MUIA_String_Contents, fname);
    }

    return 0;
}

static APTR build_gui(void)
{
    APTR app, ui, ok, browse_button1, browse_button2, browse_button3, browse_button4, cancel;

#ifdef AMIGA_MORPHOS
    static const struct Hook BrowseFileHook1 = { { NULL, NULL }, (VOID *)HookEntry, (VOID *)Browse1, NULL };
    static const struct Hook BrowseFileHook2 = { { NULL, NULL }, (VOID *)HookEntry, (VOID *)Browse2, NULL };
    static const struct Hook BrowseFileHook3 = { { NULL, NULL }, (VOID *)HookEntry, (VOID *)Browse3, NULL };
    static const struct Hook BrowseFileHook4 = { { NULL, NULL }, (VOID *)HookEntry, (VOID *)Browse4, NULL };
#else
    static const struct Hook BrowseFileHook1 = { { NULL, NULL }, (VOID *)Browse1, NULL, NULL };
    static const struct Hook BrowseFileHook2 = { { NULL, NULL }, (VOID *)Browse2, NULL, NULL };
    static const struct Hook BrowseFileHook3 = { { NULL, NULL }, (VOID *)Browse3, NULL, NULL };
    static const struct Hook BrowseFileHook4 = { { NULL, NULL }, (VOID *)Browse4, NULL, NULL };
#endif

    app = mui_get_app();

    ui = GroupObject,
           FILENAME(ui_to_from[0].object, translate_text(IDS_IDE64_FILENAME_1), browse_button1)
           FILENAME(ui_to_from[1].object, translate_text(IDS_IDE64_FILENAME_2), browse_button2)
           FILENAME(ui_to_from[2].object, translate_text(IDS_IDE64_FILENAME_3), browse_button3)
           FILENAME(ui_to_from[3].object, translate_text(IDS_IDE64_FILENAME_4), browse_button4)

           CYCLE(ui_to_from[4].object, translate_text(IDS_IDE64_V4), ui_ide64_autodetect)
           CYCLE(ui_to_from[5].object, translate_text(IDS_AUTODETECT), ui_ide64_autodetect)
           Child, ui_to_from[6].object = StringObject,
             MUIA_Frame, MUIV_Frame_String,
             MUIA_FrameTitle, translate_text(IDS_CYLINDERS),
             MUIA_String_Accept, "0123456789",
             MUIA_String_MaxLen, 4+1,
           End,
           Child, ui_to_from[7].object = StringObject,
             MUIA_Frame, MUIV_Frame_String,
             MUIA_FrameTitle, translate_text(IDS_HEADS),
             MUIA_String_Accept, "0123456789",
             MUIA_String_MaxLen, 2+1,
           End,
           Child, ui_to_from[8].object = StringObject,
             MUIA_Frame, MUIV_Frame_String,
             MUIA_FrameTitle, translate_text(IDS_SECTORS),
             MUIA_String_Accept, "0123456789",
             MUIA_String_MaxLen, 2+1,
           End,
           OK_CANCEL_BUTTON
         End;

    if (ui != NULL) {
        DoMethod(cancel, MUIM_Notify, MUIA_Pressed, FALSE,
                 app, 2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);

        DoMethod(ok, MUIM_Notify, MUIA_Pressed, FALSE,
                 app, 2, MUIM_Application_ReturnID, BTN_OK);

        DoMethod(browse_button1, MUIM_Notify, MUIA_Pressed, FALSE,
                 app, 2, MUIM_CallHook, &BrowseFileHook1);

        DoMethod(browse_button2, MUIM_Notify, MUIA_Pressed, FALSE,
                 app, 2, MUIM_CallHook, &BrowseFileHook2);

        DoMethod(browse_button3, MUIM_Notify, MUIA_Pressed, FALSE,
                 app, 2, MUIM_CallHook, &BrowseFileHook3);

        DoMethod(browse_button4, MUIM_Notify, MUIA_Pressed, FALSE,
                 app, 2, MUIM_CallHook, &BrowseFileHook4);
    }

    return ui;
}

void ui_ide64_settings_dialog(video_canvas_t *canvas)
{
    APTR window;

    ide64_canvas = canvas;
    intl_convert_mui_table(ui_ide64_autodetect_translate, ui_ide64_autodetect);

    window = mui_make_simple_window(build_gui(), translate_text(IDS_IDE64_SETTINGS));

    if (window != NULL) {
        mui_add_window(window);
        ui_get_to(ui_to_from);
        set(window, MUIA_Window_Open, TRUE);
        if (mui_run() == BTN_OK) {
            ui_get_from(ui_to_from);
        }
        set(window, MUIA_Window_Open, FALSE);
        mui_rem_window(window);
        MUI_DisposeObject(window);
    }
}
