/*
 * ui.c - Common UI routines.
 *
 * Written by
 *  Hannu Nuotio <hannu.nuotio@tut.fi>
 *
 * Based on code by
 *  Andreas Boose <viceteam@t-online.de>
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

#include <SDL/SDL.h>
#include <stdio.h>

#include "color.h"
#include "fullscreenarch.h"
#include "interrupt.h"
#include "joy.h"
#include "kbd.h"
#include "lib.h"
#include "machine.h"
#include "mouse.h"
#include "mousedrv.h"
#include "resources.h"
#include "types.h"
#include "ui.h"
#include "uiapi.h"
#include "uicolor.h"
#include "uimenu.h"
#include "uimsgbox.h"
#include "videoarch.h"
#include "vkbd.h"
#include "vsync.h"

#ifndef SDL_DISABLE
#define SDL_DISABLE SDL_IGNORE
#endif

/* ----------------------------------------------------------------- */
/* ui.h */

static char *ui_machine_name=NULL;

void ui_display_speed(float percent, float framerate, int warp_flag)
{
    char caption[100];

    sprintf(caption, "%s - %d%%/%d fps %s", ui_machine_name, (int)(percent + .5), (int)(framerate + .5), warp_flag ? "(warp)" : "");
    SDL_WM_SetCaption(caption, "VICE");
}

void ui_display_paused(int flag){}
void ui_dispatch_next_event(void){}

/* Misc. SDL event handling */
void ui_handle_misc_sdl_event(SDL_Event e)
{
    switch (e.type) {
        case SDL_QUIT:
            ui_sdl_quit();
            break;
        case SDL_ACTIVEEVENT:
            if (e.active.state & SDL_APPACTIVE) {
                if (e.active.gain) {
/*fprintf(stderr,"%s: activeevent %i,%i\n",__func__,e.active.state,e.active.gain);*/
                } else {
                }
            }
            break;
        case SDL_VIDEORESIZE:
/*fprintf(stderr,"%s: videoresize %ix%i\n",__func__,e.resize.w,e.resize.h);*/
            sdl_video_resize(e.resize.w, e.resize.h);
            break;
        default:
/*fprintf(stderr,"%s: %i\n",__func__,e.type);*/
            break;
    }
}

/* Main event handler */
ui_menu_action_t ui_dispatch_events(void)
{
    SDL_Event e;
    ui_menu_action_t retval = MENU_ACTION_NONE;

    while (SDL_PollEvent(&e)) {
        switch (e.type) {
            case SDL_KEYDOWN:
                retval = sdlkbd_press(e.key.keysym.sym, e.key.keysym.mod);
                break;
            case SDL_KEYUP:
                retval = sdlkbd_release(e.key.keysym.sym, e.key.keysym.mod);
                break;
            case SDL_JOYAXISMOTION:
                retval = sdljoy_axis_event(e.jaxis.which, e.jaxis.axis, e.jaxis.value);
                break;
            case SDL_JOYBUTTONDOWN:
                retval = sdljoy_button_event(e.jbutton.which, e.jbutton.button, 1);
                break;
            case SDL_JOYBUTTONUP:
                retval = sdljoy_button_event(e.jbutton.which, e.jbutton.button, 0);
                break;
            case SDL_JOYHATMOTION:
                retval = sdljoy_hat_event(e.jhat.which, e.jhat.hat, e.jhat.value);
                break;
            case SDL_MOUSEMOTION:
                if (_mouse_enabled) {
                    mouse_move((int)(e.motion.xrel), (int)(e.motion.yrel));
                }
                break;
            case SDL_MOUSEBUTTONDOWN:
            case SDL_MOUSEBUTTONUP:
                if (_mouse_enabled) {
                    mouse_button((int)(e.button.button), (e.button.state == SDL_PRESSED));
                }
                break;
            default:
                ui_handle_misc_sdl_event(e);
                break;
        }
        /* When using the menu or vkbd, pass every meaningful event to the caller */
        if (((sdl_menu_state)||(sdl_vkbd_state)) && (retval != MENU_ACTION_NONE) && (retval != MENU_ACTION_NONE_RELEASE)) {
            break;
        }
    }
    return retval;
}

void ui_check_mouse_cursor(void)
{
    if(_mouse_enabled && !sdl_menu_state) {
        SDL_ShowCursor(SDL_DISABLE);
        SDL_WM_GrabInput(SDL_GRAB_ON);
    } else {
        SDL_ShowCursor(sdl_active_canvas->fullscreenconfig->enable?SDL_DISABLE:SDL_ENABLE);
        SDL_WM_GrabInput(SDL_GRAB_OFF);
    }
}

void archdep_ui_init(int argc, char *argv[])
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif
}

void ui_message(const char* format, ...)
{
    va_list ap;
    char *tmp;

    va_start(ap, format);
    tmp = lib_mvsprintf(format,ap);
    va_end(ap);

    message_box("VICE MESSAGE", tmp, MESSAGE_OK);

    lib_free(tmp);
}

static int is_paused = 0;

static void pause_trap(WORD addr, void *data)
{
    ui_display_paused(1);
    is_paused = 1;
    vsync_suspend_speed_eval();
    while (is_paused) {
        ui_dispatch_next_event();
    }
}

void ui_pause_emulation(int flag)
{
    if (flag) {
        interrupt_maincpu_trigger_trap(pause_trap, 0);
    } else {
        ui_display_paused(0);
        is_paused = 0;
    }
}

int ui_emulation_is_paused(void)
{
    return is_paused;
}

/* ----------------------------------------------------------------- */
/* uiapi.h */

static int save_resources_on_exit;
static int confirm_on_exit;

static int set_ui_menukey(int val, void *param)
{
    sdl_ui_menukeys[(ui_menu_action_t)param] = val;
    return 0;
}

static int set_save_resources_on_exit(int val, void *param)
{
    save_resources_on_exit = val;
    return 0;
}

static int set_confirm_on_exit(int val, void *param)
{
    confirm_on_exit = val;
    return 0;
}

static const resource_int_t resources_int[] = {
    { "MenuKey", SDLK_F9, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[0], set_ui_menukey, (void *)MENU_ACTION_NONE },
    { "MenuKeyUp", SDLK_UP, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[1], set_ui_menukey, (void *)MENU_ACTION_UP },
    { "MenuKeyDown", SDLK_DOWN, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[2], set_ui_menukey, (void *)MENU_ACTION_DOWN },
    { "MenuKeyLeft", SDLK_LEFT, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[3], set_ui_menukey, (void *)MENU_ACTION_LEFT },
    { "MenuKeyRight", SDLK_RIGHT, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[4], set_ui_menukey, (void *)MENU_ACTION_RIGHT },
    { "MenuKeySelect", SDLK_RETURN, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[5], set_ui_menukey, (void *)MENU_ACTION_SELECT },
    { "MenuKeyCancel", SDLK_BACKSPACE, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[6], set_ui_menukey, (void *)MENU_ACTION_CANCEL },
    { "MenuKeyExit", SDLK_ESCAPE, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[7], set_ui_menukey, (void *)MENU_ACTION_EXIT },
    { "MenuKeyMap", SDLK_m, RES_EVENT_NO, NULL,
      &sdl_ui_menukeys[8], set_ui_menukey, (void *)MENU_ACTION_MAP },
    { "SaveResourcesOnExit", 0, RES_EVENT_NO, NULL,
      &save_resources_on_exit, set_save_resources_on_exit, NULL },
    { "ConfirmOnExit", 0, RES_EVENT_NO, NULL,
      &confirm_on_exit, set_confirm_on_exit, NULL },
    { NULL },
};

void ui_sdl_quit(void)
{
    if (confirm_on_exit) {
        if (message_box("VICE QUESTION","Do you really want to exit?", MESSAGE_YESNO) == 1) {
            return;
        }
    }

    if (save_resources_on_exit) {
        if (resources_save(NULL) < 0) {
            ui_error("Cannot save current settings.");
        }
    }
    exit(0);
}

/* Initialization  */
int ui_resources_init(void)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    return resources_register_int(resources_int);
}

void ui_resources_shutdown(void)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif
}

int ui_cmdline_options_init(void)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    return 0;
}

int ui_init(int *argc, char **argv)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    switch (machine_class) {
        case VICE_MACHINE_C64:
            ui_machine_name = "VICE C64 Emulator";
            break;
      case VICE_MACHINE_C64DTV:
            ui_machine_name = "VICE C64DTV Emulator";
            break;
      case VICE_MACHINE_C128:
            ui_machine_name = "VICE C128 Emulator";
            break;
      case VICE_MACHINE_CBM2:
            ui_machine_name = "VICE CBM2 Emulator";
            break;
      case VICE_MACHINE_PET:
            ui_machine_name = "VICE PET Emulator";
            break;
      case VICE_MACHINE_PLUS4:
            ui_machine_name = "VICE PLUS4 Emulator";
            break;
      case VICE_MACHINE_VIC20:
            ui_machine_name = "VICE VIC20 Emulator";
            break;
    }

    /* TODO move somewhere else */
    sdlkbd_init_resources();

    return 0;
}

int ui_init_finish(void)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    return 0;
}

int ui_init_finalize(void)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    SDL_WM_SetCaption(ui_machine_name, "VICE");
    return 0;
}

void ui_shutdown(void)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    /* TODO find a better place */
    kbd_arch_shutdown();
}

/* Print an error message.  */
void ui_error(const char *format,...)
{
    va_list ap;
    char *tmp;

    va_start(ap, format);
    tmp = lib_mvsprintf(format, ap);
    va_end(ap);

    message_box("VICE ERROR", tmp, MESSAGE_OK);

    lib_free(tmp);
}


/* Display a mesage without interrupting emulation */
void ui_display_statustext(const char *text, int fade_out){}

/* Let the user browse for a filename; display format as a titel */
extern char* ui_get_file(const char *format,...)
{
    return NULL;
}

/* Drive related UI.  */
void ui_enable_drive_status(ui_drive_enable_t state,
                            int *drive_led_color){}
void ui_display_drive_track(unsigned int drive_number,
                            unsigned int drive_base,
                            unsigned int half_track_number){}
/* The pwm value will vary between 0 and 1000.  */
void ui_display_drive_led(int drive_number, unsigned int pwm1,
                          unsigned int led_pwm2){}
void ui_display_drive_current_image(unsigned int drive_number,
                                    const char *image){}
int ui_extend_image_dialog(void)
{
    if (message_box("VICE QUESTION", "Extend image to 40-track format?", MESSAGE_YESNO) == 0) {
        return 1;
    }
    return 0;
}

/* Tape related UI */
void ui_set_tape_status(int tape_status){}
void ui_display_tape_motor_status(int motor){}
void ui_display_tape_control_status(int control){}
void ui_display_tape_counter(int counter){}
void ui_display_tape_current_image(const char *image){}

/* Show a CPU JAM dialog.  */
ui_jam_action_t ui_jam_dialog(const char *format, ...)
{
    int retval;

    retval = message_box("VICE CPU JAM", "a CPU JAM has occured, choose the action to take", MESSAGE_CPUJAM);
    if (retval == 0) {
        return UI_JAM_HARD_RESET;
    }
    if (retval == 1) {
        return UI_JAM_MONITOR;
    }
    return UI_JAM_NONE;
}

/* Update all menu entries.  */
void ui_update_menus(void){}

/* Recording UI */
void ui_display_playback(int playback_status, char *version){}
void ui_display_recording(int recording_status){}
void ui_display_event_time(unsigned int current, unsigned int total){}

/* Joystick UI */
void ui_display_joyport(BYTE *joyport){}

/* Volume UI */
void ui_display_volume(int vol){}

/* ----------------------------------------------------------------- */
/* uicolor.h */

int uicolor_alloc_color(unsigned int red, unsigned int green,
                        unsigned int blue, unsigned long *color_pixel,
                        BYTE *pixel_return)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    return 0;
}

void uicolor_free_color(unsigned int red, unsigned int green,
                        unsigned int blue, unsigned long color_pixel)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif
}

void uicolor_convert_color_table(unsigned int colnr, BYTE *data,
                                 long color_pixel, void *c)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif
}

int uicolor_set_palette(struct video_canvas_s *c,
                        const struct palette_s *palette)
{
#ifdef SDL_DEBUG
fprintf(stderr,"%s\n",__func__);
#endif

    return 0;
}
