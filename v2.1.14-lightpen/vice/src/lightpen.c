/*
 * lightpen.c - Lightpen/gun emulation
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

#include <stdio.h>

#include "cmdline.h"
#include "joystick.h"
#include "machine.h"
#include "maincpu.h"
#include "lightpen.h"
#include "resources.h"
#include "translate.h"


#define MAX_WINDOW_NUM 1

/* --------------------------------------------------------- */
/* extern variables */

int lightpen_enabled = 0;
int lightpen_type;


/* --------------------------------------------------------- */
/* static variables/functions */

static int lightpen_buttons;
static int lightpen_button_y;
static int lightpen_button_x;

static lightpen_timing_callback_ptr_t chip_timing_callback[MAX_WINDOW_NUM + 1];
static lightpen_trigger_callback_ptr_t chip_trigger_callback;

struct lp_type_s {
    enum { PEN, GUN } type;
    BYTE button1;
    BYTE button2;
};
typedef struct lp_type_s lp_type_t;

static const lp_type_t lp_type[LIGHTPEN_TYPE_NUM] = {
    { PEN, 0x00, 0x01 },
    { PEN, 0x00, 0x04 },
    { GUN, 0x20, 0x00 },
    { GUN, 0x04, 0x00 }
};

static inline void lightpen_check_button_mask(BYTE mask, int pressed)
{
    if (!mask) {
        return;
    }

    if (pressed) {
        joystick_set_value_or(1, mask);
    } else {
        joystick_set_value_and(1, (BYTE)~mask);
    }
}

static inline void lightpen_update_buttons(int buttons)
{
    lightpen_buttons = buttons;

    lightpen_button_y = ((((lp_type[lightpen_type].button1 & 0x20) == 0x20) && (buttons & 1))
                      || (((lp_type[lightpen_type].button2 & 0x20) == 0x20) && (buttons & 2)))
                      ? 1 : 0;

    lightpen_button_x = ((((lp_type[lightpen_type].button1 & 0x40) == 0x40) && (buttons & 1))
                      || (((lp_type[lightpen_type].button2 & 0x40) == 0x40) && (buttons & 2)))
                      ? 1 : 0;

    lightpen_check_button_mask(lp_type[lightpen_type].button1 & 0xf, buttons & 2);
    lightpen_check_button_mask(lp_type[lightpen_type].button2 & 0xf, buttons & 4);
}

/* --------------------------------------------------------- */
/* Resources & cmdline */

static int set_lightpen_enabled(int val, void *param)
{
    lightpen_enabled = val;
    return 0;
}

static int set_lightpen_type(int val, void *param)
{
    if (!((val >= 0) && (val < LIGHTPEN_TYPE_NUM))) {
        return -1;
    }

    lightpen_type = val;

    return 0;
}

static const resource_int_t resources_int[] = {
    { "Lightpen", 0, RES_EVENT_SAME, NULL,
      &lightpen_enabled, set_lightpen_enabled, NULL },
    { "LightpenType", LIGHTPEN_TYPE_PEN_U, RES_EVENT_SAME, NULL,
      &lightpen_type, set_lightpen_type, NULL },
    { NULL }
};

int lightpen_resources_init(void)
{
    return resources_register_int(resources_int);
}

static const cmdline_option_t cmdline_options[] = {
    { "-lightpen", SET_RESOURCE, 0,
      NULL, NULL, "Lightpen", (void *)1,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDCLS_UNUSED, IDCLS_UNUSED,
      NULL, T_("Enable lightpen emulation") },
    { "+lightpen", SET_RESOURCE, 0,
      NULL, NULL, "Lightpen", (void *)0,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDCLS_UNUSED, IDCLS_UNUSED,
      NULL, T_("Disable lightpen emulation") },
    { "-lightpentype", SET_RESOURCE, 1,
      NULL, NULL, "LightpenType", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDCLS_UNUSED, IDCLS_UNUSED,
      T_("<type>"), T_("Set lightpen type") },
    { NULL }
};

int lightpen_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}

/* --------------------------------------------------------- */
/* Main API */

void lightpen_init(void)
{
    int i;

    for (i = 0; i < (MAX_WINDOW_NUM + 1); ++i) {
        chip_timing_callback[i] = NULL;
    }
}

int lightpen_register_timing_callback(lightpen_timing_callback_ptr_t timing_callback, int window)
{
    if ((window < 0) || (window > MAX_WINDOW_NUM)) {
        return -1;
    }

    chip_timing_callback[window] = timing_callback;
    return 0;
}

int lightpen_register_trigger_callback(lightpen_trigger_callback_ptr_t trigger_callback)
{
    chip_trigger_callback = trigger_callback;
    return 0;
}

void lightpen_update(int window, int x, int y, int buttons)
{
    CLOCK pulse_time;

    if ((window < 0) || (window > MAX_WINDOW_NUM)) {
        return;
    }

    if ((!lightpen_enabled) || (chip_timing_callback[window] == NULL) || (chip_trigger_callback == NULL)) {
        return;
    }

    lightpen_update_buttons(buttons);

    if ((x < 0) || (y < 0)) {
        return;
    }

    if ((lp_type[lightpen_type].type == PEN) && !(buttons & 1)) {
        return;
    }

    pulse_time = chip_timing_callback[window](x, y);

    if (pulse_time > 0) {
        chip_trigger_callback(pulse_time);
    }
}

BYTE lightpen_read_button_y(void)
{
    return (lightpen_enabled && lightpen_button_y) ? 0x00 : 0xff;
}

BYTE lightpen_read_button_x(void)
{
    return (lightpen_enabled && lightpen_button_x) ? 0x00 : 0xff;
}
