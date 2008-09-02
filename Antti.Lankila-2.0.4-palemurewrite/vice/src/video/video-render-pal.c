/*
 * video-render-pal.c - Implementation of framebuffer to physical screen copy
 *
 * Written by
 *  John Selck <graham@cruise.de>
 *  Dag Lem <resid@nimrod.no>
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

#include <stdio.h>

#include "render1x1.h"
#include "render1x1pal.h"
#include "render2x2.h"
#include "render2x2pal.h"
#include "renderscale2x.h"
#include "types.h"
#include "video-render.h"
#include "video-resources.h"
#include "video.h"


static void video_render_pal_main(video_render_config_t *config,
                                  BYTE *src, BYTE *trg,
                                  int width, int height, int xs, int ys, int xt,
                                  int yt, int pitchs, int pitcht, int depth, int viewport_height)
{
    video_render_color_tables_t *colortab;
    int doublescan, delayloop, rendermode, palmode, scale2x;

    rendermode = config->rendermode;
    doublescan = config->doublescan;
    colortab = &config->color_tables;
    scale2x = config->scale2x;

    delayloop = video_resources.delayloop_emulation;

    /*
    if (config->external_palette)
        delayloop = 0;
    */

    palmode = video_resources.pal_mode;

    if ((rendermode == VIDEO_RENDER_PAL_1X1
        || rendermode == VIDEO_RENDER_PAL_2X2)
        && video_resources.pal_scanlineshade <= 0)
        doublescan = 0;

    switch (rendermode) {
      case VIDEO_RENDER_NULL:
        break;

      case VIDEO_RENDER_PAL_1X1:
        if (delayloop) {
            switch (depth) {
              case 8:
                render_08_1x1_08(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 16:
                switch (palmode) {
                  default:
                  case VIDEO_RESOURCE_PAL_MODE_FAST:
                    render_16_1x1_08(colortab, src, trg, width, height,
                                     xs, ys, xt, yt, pitchs, pitcht);
                    return;
                  case VIDEO_RESOURCE_PAL_MODE_TRUE:
                  case VIDEO_RESOURCE_PAL_MODE_NEW:
                    render_16_1x1_pal(colortab, src, trg, width, height,
                                        xs, ys, xt, yt, pitchs, pitcht);
                    return;
                }
                return;
              case 24:
                render_24_1x1_08(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 32:
                switch (palmode) {
                  default:
                  case VIDEO_RESOURCE_PAL_MODE_FAST:
                    render_32_1x1_08(colortab, src, trg, width, height,
                                     xs, ys, xt, yt, pitchs, pitcht);
                    return;
                  case VIDEO_RESOURCE_PAL_MODE_TRUE:
                  case VIDEO_RESOURCE_PAL_MODE_NEW:
                    render_32_1x1_pal(colortab, src, trg, width, height,
                                      xs, ys, xt, yt, pitchs, pitcht);
					return;
                }
                return;
            }
        } else {
            switch (depth) {
              case 8:
                render_08_1x1_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 16:
                render_16_1x1_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 24:
                render_24_1x1_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 32:
                render_32_1x1_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
            }
        }
        return;
      case VIDEO_RENDER_PAL_2X2:
        if (delayloop) {
            switch (depth) {
              case 8:
                render_08_2x2_08(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht, doublescan);
                return;
              case 16:
                switch (palmode) {
                  default:
                  case VIDEO_RESOURCE_PAL_MODE_FAST:
                    render_16_2x2_08(colortab, src, trg, width, height,
                                     xs, ys, xt, yt, pitchs, pitcht,
                                     doublescan);
                    return;
                  case VIDEO_RESOURCE_PAL_MODE_TRUE:
                  case VIDEO_RESOURCE_PAL_MODE_NEW:
                    render_16_2x2_pal(colortab, src, trg, width, height,
                                      xs, ys, xt, yt, pitchs, pitcht,
                                      viewport_height);
                    return;
                }
                return;
              case 24:
                switch (palmode) {
                  default:
                  case VIDEO_RESOURCE_PAL_MODE_FAST:
			render_24_2x2_08(colortab, src, trg, width, height,
					 xs, ys, xt, yt, pitchs, pitcht, doublescan);
                    return;
                  case VIDEO_RESOURCE_PAL_MODE_TRUE:
                  case VIDEO_RESOURCE_PAL_MODE_NEW:
                    render_24_2x2_pal(colortab, src, trg, width, height,
                                      xs, ys, xt, yt, pitchs, pitcht,
                                      viewport_height);
                    return;
                }
                return;
              case 32:
                switch (palmode) {
                  default:
                  case VIDEO_RESOURCE_PAL_MODE_FAST:
                    render_32_2x2_08(colortab, src, trg, width, height,
                                     xs, ys, xt, yt, pitchs, pitcht,
                                     doublescan);
                    return;
                  case VIDEO_RESOURCE_PAL_MODE_TRUE:
                  case VIDEO_RESOURCE_PAL_MODE_NEW:
                    render_32_2x2_pal(colortab, src, trg, width, height,
                                      xs, ys, xt, yt, pitchs, pitcht,
                                      viewport_height);
                    return;
                }
                return;
            }
        } else if (scale2x) {
            switch (depth) {
              case 8:
                render_08_scale2x(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 16:
                render_16_scale2x(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 24:
                render_24_scale2x(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
              case 32:
                render_32_scale2x(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht);
                return;
            }
        } else {
            switch (depth) {
              case 8:
                render_08_2x2_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht, doublescan);
                return;
              case 16:
                render_16_2x2_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht, doublescan);
                return;
              case 24:
                render_24_2x2_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht, doublescan);
                return;
              case 32:
                render_32_2x2_04(colortab, src, trg, width, height,
                                 xs, ys, xt, yt, pitchs, pitcht, doublescan);
                return;
            }
        }
    }
}

void video_render_pal_init(void)
{
    video_render_palfunc_set(video_render_pal_main);
}

