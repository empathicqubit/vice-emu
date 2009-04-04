/*
 * menu_help.c - SDL help menu functions.
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
#include <SDL/SDL.h>

#include "cmdline.h"
#include "info.h"
#include "lib.h"
#include "menu_common.h"
#include "menu_help.h"
#include "ui.h"
#include "uimenu.h"
#include "util.h"
#include "version.h"

static char *convert_cmdline_to_40_cols(char *text)
{
    char *new_text;
    int num_options;
    int current_line;
    int i, j, k, index;

    num_options = cmdline_get_num_options();
    new_text = (char *)lib_malloc(strlen(text) + num_options);

    new_text[0] = '\n';
    index = 1;
    current_line = 1;
    for (i = 0; i < num_options; i++) {
        for (j = 0; text[current_line + j] != '\n'; j++) {
            new_text[index] = text[current_line + j];
            index++;
        }
        new_text[index] = '\n';
        index++;
        current_line += j + 2;
        for (j = 0; text[current_line + j] != '\n'; j++) {
            new_text[index + j] = text[current_line + j];
        }
        new_text[index + j] = '\n';
        if (j > 40) {
            for (k = 39; text[current_line + k] != ' '; k--);
            new_text[index + k] = '\n';
        }
        current_line += j + 1;
        index += j + 1;
        new_text[index] = '\n';
        index++;
    }
    return new_text;
}

static void make_40_cols(char *text)
{
    int i = 40;

    while (i < (strlen(text) -1)) {
        while (text[i] != ' ') {
            i--;
        }
        text[i] = '\n';
        i += 40;
    }
}

static char *contrib_convert(char *text)
{
    char *new_text;
    char *pos;
    int i=0;
    int j=0;
    int single=0;

    new_text = (char *)malloc(strlen(text));
    while (i < strlen(text)) {
        if (text[i] == ' ' && text[i + 1] == ' ' && text[i - 1] == '\n') {
            i += 2;
        } else {
            if ((text[i] == ' ' || text[i] == '\n') && text[i + 1] == '<') {
                while (text[i] != '>') {
                   i++;
                }
                i++;
            } else {
                new_text[j] = text[i];
                j++;
                i++;
            }
        }
    }
    new_text[j] = 0;

    i = 0;
    j = strlen(new_text);

    while (i < j) {
        if (new_text[i] == '\n') {
            if (new_text[i + 1] == '\n') {
                if (single) {
                    single = 0;
                }
                if (new_text[i - 1] == ':' && new_text[i - 2] == 'e') {
                    single = 1;
                }
                new_text[i + 1] = 0;
                i++;
            } else {
                if (!single) {
                    new_text[i] = ' ';
                }
            }
        }
        i++;
    }
    pos = new_text;
    while (*pos != 0) {
        make_40_cols(pos);
        pos += strlen(pos) + 1;
    }

    for (i = 0; i < j; i++) {
        if (new_text[i] == 0) {
            new_text[i] = '\n';
        }
    }

    return new_text;
}

static void show_text(const char *text)
{
    int next_line = 0;
    int next_page = 0;
    int current_line = 0;
    int x, y, z;
    int active = 1;
    int active_keys;
    char *string;
    menu_draw_t *menu_draw;

    menu_draw = sdl_ui_get_menu_param();

    string = lib_malloc(81);
    while(active) {
        sdl_ui_clear();
        for (y = 0; (y < menu_draw->max_text_y) && (current_line < strlen(text)); y++) {
            z = 0;
            for (x = 0; text[current_line + x] != '\n'; x++) {
                switch (text[current_line + x]) {
                    case '`':
                        string[x + z] = '\'';
                        break;
                    case '�':
                        string[x + z] = 'a';
                        break;
                    case '~':
                        string[x + z] = '-';
                        break;
                    case '�':
                    case '�':
                        string[x + z] = 'e';
                        break;
                    case '�':
                        string[x + z] = 'O';
                        break;
                    case '�':
                        string[x + z] = 'o';
                        break;
                    case '�':
                        string[x + z] = 'a';
                        break;
                    case '\t':
                        string[x + z] = ' ';
                        string[x + z + 1] = ' ';
                        string[x + z + 2] = ' ';
                        string[x + z + 3] = ' ';
                        z += 3;
                        break;
                    default:
                       string[x + z] = text[current_line + x];
                       break;
                }
            }
            if (x != 0) {
                string[x + z] = 0;
                sdl_ui_print(string, 0, y);
            }
            if (y == 0) {
                next_line = current_line + x + 1;
            }
            current_line += x + 1;
        }
        next_page = current_line;
        active_keys = 1;
        sdl_ui_refresh();
        while (active_keys) {
            switch(sdl_ui_menu_poll_input()) {
                case MENU_ACTION_CANCEL:
                case MENU_ACTION_EXIT:
                    active_keys = 0;
                    active = 0;
                    break;
                case MENU_ACTION_RIGHT:
                    active_keys = 0;
                    current_line = next_page;
                    break;
                case MENU_ACTION_DOWN:
                    active_keys = 0;
                    current_line = next_line;
                    break;
                default:
                    SDL_Delay(10);
                    break;
            }
        }
    }
    lib_free(string);
}

static UI_MENU_CALLBACK(about_callback)
{
    int active = 1;

    if (activated) {
        sdl_ui_clear();
        sdl_ui_print_center("VICE", 0);
        sdl_ui_print_center("Versatile Commodore Emulator", 1);
        sdl_ui_print_center("Version " VERSION, 2);
        sdl_ui_print_center("The VICE Team", 4);
        sdl_ui_print_center("(C) 1998-2009 Andreas Boose", 5);
        sdl_ui_print_center("(C) 1998-2009 Tibor Biczo", 6);
        sdl_ui_print_center("(C) 1999-2009 Andreas Matthies", 7);
        sdl_ui_print_center("(C) 1999-2009 Martin Pottendorfer", 8);
        sdl_ui_print_center("(C) 1998-2009 Dag Lem", 9);
        sdl_ui_print_center("(C) 2000-2009 Spiro Trikaliotis", 10);
        sdl_ui_print_center("(C) 2005-2009 Marco van den Heuvel", 11);
        sdl_ui_print_center("(C) 2006-2009 Christian Vogelgsang", 12);
        sdl_ui_print_center("(C) 2007-2009 Fabrizio Gennari", 13);
        sdl_ui_print_center("(C) 2007-2009 M. Kiesel", 14);
        sdl_ui_print_center("(C) 2007-2009 Hannu Nuotio", 15);
        sdl_ui_print_center("(C) 2007-2009 Daniel Kahlin", 16);
        sdl_ui_print_center("(C) 2008-2009 Antti S. Lankila", 17);
        sdl_ui_refresh();
        while(active) {
            switch(sdl_ui_menu_poll_input()) {
                case MENU_ACTION_CANCEL:
                case MENU_ACTION_EXIT:
                    active = 0;
                    break;
                default:
                    SDL_Delay(10);
                    break;
            }
        }
    }
    return NULL;
}

static UI_MENU_CALLBACK(cmdline_callback)
{
    menu_draw_t *menu_draw;
    char *options;
    char *options40;

    if (activated) {
        menu_draw = sdl_ui_get_menu_param();
        if (menu_draw->max_text_x > 60) {
            options = cmdline_options_string();
            show_text((const char *)options);
            lib_free(options);
        } else {
            options = cmdline_options_string();
            options40 = convert_cmdline_to_40_cols(options);
            lib_free(options);
            show_text((const char *)options40);
            lib_free(options40);
        }
    }
    return NULL;
}

static UI_MENU_CALLBACK(contributors_callback)
{
    menu_draw_t *menu_draw;
    char *info_contrib_text40;

    if (activated) {
        menu_draw = sdl_ui_get_menu_param();
        if (menu_draw->max_text_x > 60) {
            show_text((const char *)info_contrib_text);
        } else {
            info_contrib_text40 = contrib_convert((char *)info_contrib_text);
            show_text((const char *)info_contrib_text40);
            lib_free(info_contrib_text40);
        }
    }
    return NULL;
}

static UI_MENU_CALLBACK(license_callback)
{
    menu_draw_t *menu_draw;

    if (activated) {
        menu_draw = sdl_ui_get_menu_param();
        if (menu_draw->max_text_x > 60) {
            show_text(info_license_text);
        } else {
            show_text(info_license_text40);
        }
    }
    return NULL;
}

static UI_MENU_CALLBACK(warranty_callback)
{
    menu_draw_t *menu_draw;

    if (activated) {
        menu_draw = sdl_ui_get_menu_param();
        if (menu_draw->max_text_x > 60) {
            show_text(info_warranty_text);
        } else {
            show_text(info_warranty_text40);
        }
    }
    return NULL;
}

const ui_menu_entry_t help_menu[] = {
    { "About",
      MENU_ENTRY_DIALOG,
      about_callback,
      NULL },
    { "Command-line options",
      MENU_ENTRY_DIALOG,
      cmdline_callback,
      NULL },
    { "Contributors",
      MENU_ENTRY_DIALOG,
      contributors_callback,
      NULL },
    { "License",
      MENU_ENTRY_DIALOG,
      license_callback,
      NULL },
    { "Warranty",
      MENU_ENTRY_DIALOG,
      warranty_callback,
      NULL },
    { NULL }
};
