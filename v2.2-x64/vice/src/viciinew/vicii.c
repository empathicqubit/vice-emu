/*
 * vicii.c - A cycle-exact event-driven MOS6569 (VIC-II) emulation.
 *
 * Written by
 *  Ettore Perazzoli <ettore@comm2000.it>
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

/* TODO: - speed optimizations;
   - faster sprites and registers.  */

/*
   Current (most important) known limitations:

   - sprite colors (and other attributes) cannot change in the middle of the
   raster line;

   Probably something else which I have not figured out yet...

 */

#include "vice.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c64.h"
#include "cartridge.h"
#include "c64cart.h"
#include "lib.h"
#include "log.h"
#include "machine.h"
#include "maincpu.h"
#include "mem.h"
#include "raster-line.h"
#include "raster-modes.h"
#include "raster-sprite-status.h"
#include "raster-sprite.h"
#include "resources.h"
#include "screenshot.h"
#include "types.h"
#include "vicii-cmdline-options.h"
#include "vicii-color.h"
#include "vicii-draw.h"
#include "vicii-draw-cycle.h"
#include "vicii-fetch.h"
#include "vicii-irq.h"
#include "vicii-mem.h"
#include "vicii-sprites.h"
#include "vicii-resources.h"
#include "vicii-timing.h"
#include "vicii.h"
#include "viciitypes.h"
#include "vsync.h"
#include "video.h"
#include "videoarch.h"
#include "viewport.h"


void vicii_set_phi1_addr_options(WORD mask, WORD offset)
{
    vicii.vaddr_mask_phi1 = mask;
    vicii.vaddr_offset_phi1 = offset;

    VICII_DEBUG_REGISTER(("Set phi1 video addr mask=%04x, offset=%04x",
                         mask, offset));
    vicii_update_memory_ptrs_external();
}

void vicii_set_phi2_addr_options(WORD mask, WORD offset)
{
    vicii.vaddr_mask_phi2 = mask;
    vicii.vaddr_offset_phi2 = offset;

    VICII_DEBUG_REGISTER(("Set phi2 video addr mask=%04x, offset=%04x",
                         mask, offset));
    vicii_update_memory_ptrs_external();
}

void vicii_set_phi1_chargen_addr_options(WORD mask, WORD value)
{
    vicii.vaddr_chargen_mask_phi1 = mask;
    vicii.vaddr_chargen_value_phi1 = value;

    VICII_DEBUG_REGISTER(("Set phi1 chargen addr mask=%04x, value=%04x",
                         mask, value));
    vicii_update_memory_ptrs_external();
}

void vicii_set_phi2_chargen_addr_options(WORD mask, WORD value)
{
    vicii.vaddr_chargen_mask_phi2 = mask;
    vicii.vaddr_chargen_value_phi2 = value;

    VICII_DEBUG_REGISTER(("Set phi2 chargen addr mask=%04x, value=%04x",
                         mask, value));
    vicii_update_memory_ptrs_external();
}

void vicii_set_chargen_addr_options(WORD mask, WORD value)
{
    vicii.vaddr_chargen_mask_phi1 = mask;
    vicii.vaddr_chargen_value_phi1 = value;
    vicii.vaddr_chargen_mask_phi2 = mask;
    vicii.vaddr_chargen_value_phi2 = value;

    VICII_DEBUG_REGISTER(("Set chargen addr mask=%04x, value=%04x",
                         mask, value));
    vicii_update_memory_ptrs_external();
}

/* ---------------------------------------------------------------------*/

vicii_t vicii;

static void vicii_set_geometry(void);

void vicii_change_timing(machine_timing_t *machine_timing, int border_mode)
{
    vicii_timing_set(machine_timing, border_mode);

    if (vicii.initialized) {
        vicii_set_geometry();
        raster_mode_change();
    }
}

static CLOCK old_maincpu_clk = 0;

void vicii_delay_oldclk(CLOCK num)
{
    old_maincpu_clk += num;
}

inline void vicii_handle_pending_alarms(int num_write_cycles)
{
    return;
}

void vicii_handle_pending_alarms_external(int num_write_cycles)
{
    if (vicii.initialized)
        vicii_handle_pending_alarms(num_write_cycles);
}

void vicii_handle_pending_alarms_external_write(void)
{
    /* WARNING: assumes `maincpu_rmw_flag' is 0 or 1.  */
    if (vicii.initialized)
        vicii_handle_pending_alarms(maincpu_rmw_flag + 1);
}

static void vicii_set_geometry(void)
{
    unsigned int width, height;

    width = vicii.screen_leftborderwidth + VICII_SCREEN_XPIX + vicii.screen_rightborderwidth;
    height = vicii.last_displayed_line - vicii.first_displayed_line + 1;

    raster_set_geometry(&vicii.raster,
                        width, height, /* canvas dimensions */
                        width, vicii.screen_height, /* screen dimensions */
                        VICII_SCREEN_XPIX, VICII_SCREEN_YPIX, /* gfx dimensions */
                        VICII_SCREEN_TEXTCOLS, VICII_SCREEN_TEXTLINES, /* text dimensions */
                        vicii.screen_leftborderwidth, vicii.row_25_start_line, /* gfx position */
                        0, /* gfx area doesn't move */
                        vicii.first_displayed_line,
                        vicii.last_displayed_line,
                        - VICII_RASTER_X(0), /* extra offscreen border left */
                        vicii.sprite_wrap_x - VICII_SCREEN_XPIX -
                        vicii.screen_leftborderwidth - vicii.screen_rightborderwidth + VICII_RASTER_X(0)) /* extra offscreen border right */;
#ifdef __MSDOS__
    video_ack_vga_mode();
#endif

}

static int init_raster(void)
{
    raster_t *raster;

    raster = &vicii.raster;
    video_color_set_canvas(raster->canvas);

    raster_sprite_status_new(raster, VICII_NUM_SPRITES, vicii_sprite_offset());
    raster_line_changes_sprite_init(raster);

    if (raster_init(raster, VICII_NUM_VMODES) < 0)
        return -1;
    raster_modes_set_idle_mode(raster->modes, VICII_IDLE_MODE);
    resources_touch("VICIIVideoCache");

    vicii_set_geometry();

    if (vicii_color_update_palette(raster->canvas) < 0) {
        log_error(vicii.log, "Cannot load palette.");
        return -1;
    }

    raster_set_title(raster, machine_name);

    if (raster_realize(raster) < 0) {
        return -1;
    }

    raster->display_ystart = vicii.row_25_start_line;
    raster->display_ystop = vicii.row_25_stop_line;
    raster->display_xstart = VICII_40COL_START_PIXEL;
    raster->display_xstop = VICII_40COL_STOP_PIXEL;

    return 0;
}

/* Initialize the VIC-II emulation.  */
raster_t *vicii_init(unsigned int flag)
{
    if (flag != VICII_STANDARD) {
        return NULL;
    }

    vicii.log = log_open("VIC-II");

    vicii_irq_init();

    if (init_raster() < 0) {
        return NULL;
    }

    vicii_powerup();

    vicii.video_mode = -1;
    vicii_update_video_mode(0);
    vicii_update_memory_ptrs(0);

    vicii_draw_init();
    vicii_draw_cycle_init();
    vicii_sprites_init();

    vicii.buf_offset = 0;

    vicii.initialized = 1;

    return &vicii.raster;
}

struct video_canvas_s *vicii_get_canvas(void)
{
    return vicii.raster.canvas;
}

/* Reset the VIC-II chip.  */
void vicii_reset(void)
{
    raster_reset(&vicii.raster);

    vicii.raster_line = 0;
    vicii.raster_cycle = 6;

    vicii.sprite_fetch_idx = 0;
    vicii.sprite_fetch_msk = 0;

    /* FIXME: I am not sure this is exact emulation.  */
    vicii.raster_irq_line = 0;
    vicii.regs[0x11] = 0;
    vicii.regs[0x12] = 0;

    vicii.force_display_state = 0;

    vicii.light_pen.triggered = 0;
    vicii.light_pen.x = vicii.light_pen.y = vicii.light_pen.x_extra_bits = 0;

    /* Remove all the IRQ sources.  */
    vicii.regs[0x1a] = 0;

    vicii.raster.display_ystart = vicii.row_25_start_line;
    vicii.raster.display_ystop = vicii.row_25_stop_line;
}

void vicii_reset_registers(void)
{
    WORD i;

    if (!vicii.initialized) {
        return;
    }

    for (i = 0; i <= 0x3f; i++) {
        vicii_store(i, 0);
    }

    raster_sprite_status_reset(vicii.raster.sprite_status, vicii_sprite_offset());
}

/* This /should/ put the VIC-II in the same state as after a powerup, if
   `reset_vicii()' is called afterwards.  But FIXME, as we are not really
   emulating everything correctly here; just $D011.  */
void vicii_powerup(void)
{
    memset(vicii.regs, 0, sizeof(vicii.regs));

    vicii.irq_status = 0;
    vicii.raster_irq_line = 0;
    vicii.ram_base_phi1 = mem_ram;
    vicii.ram_base_phi2 = mem_ram;

    vicii.vaddr_mask_phi1 = 0xffff;
    vicii.vaddr_mask_phi2 = 0xffff;
    vicii.vaddr_offset_phi1 = 0;
    vicii.vaddr_offset_phi2 = 0;

    vicii.allow_bad_lines = 0;
    vicii.sprite_sprite_collisions = vicii.sprite_background_collisions = 0;
    vicii.idle_state = 0;
    vicii.force_display_state = 0;
    vicii.memptr = 0;
    vicii.mem_counter = 0;
    vicii.bad_line = 0;
    vicii.force_black_overscan_background_color = 0;
    vicii.light_pen.x = vicii.light_pen.y = vicii.light_pen.x_extra_bits = vicii.light_pen.triggered = 0;
    vicii.vbank_phi1 = 0;
    vicii.vbank_phi2 = 0;

    vicii_reset();

    vicii.raster.blank = 1;
    vicii.raster.display_ystart = vicii.row_24_start_line;
    vicii.raster.display_ystop = vicii.row_24_stop_line;

    vicii.raster.ysmooth = 0;
}

/* ---------------------------------------------------------------------*/

/* This hook is called whenever video bank must be changed.  */
static inline void vicii_set_vbanks(int vbank_p1, int vbank_p2)
{
    /* Warning: assumes it's called within a memory write access.
       FIXME: Change name?  */
    /* Also, we assume the bank has *really* changed, and do not do any
       special optimizations for the not-really-changed case.  */
    vicii_handle_pending_alarms(maincpu_rmw_flag + 1);

    vicii.vbank_phi1 = vbank_p1;
    vicii.vbank_phi2 = vbank_p2;
    vicii_update_memory_ptrs(VICII_RASTER_CYCLE(maincpu_clk));
}

/* Phi1 and Phi2 accesses */
void vicii_set_vbank(int num_vbank)
{
    int tmp = num_vbank << 14;
    vicii_set_vbanks(tmp, tmp);
}

/* Phi1 accesses */
void vicii_set_phi1_vbank(int num_vbank)
{
    vicii_set_vbanks(num_vbank << 14, vicii.vbank_phi2);
}

/* Phi2 accesses */
void vicii_set_phi2_vbank(int num_vbank)
{
    vicii_set_vbanks(vicii.vbank_phi1, num_vbank << 14);
}

/* ---------------------------------------------------------------------*/

/* Trigger the light pen.  */
void vicii_trigger_light_pen(CLOCK mclk)
{
    if (!vicii.light_pen.triggered) {
        vicii.light_pen.triggered = 1;
        vicii.light_pen.x = VICII_RASTER_X(mclk % vicii.cycles_per_line)
                                - vicii.screen_leftborderwidth + 0x20;

        if (vicii.light_pen.x < 0) {
            vicii.light_pen.x = vicii.sprite_wrap_x + vicii.light_pen.x;
        }

        /* FIXME: why `+2'? */
        vicii.light_pen.x = vicii.light_pen.x / 2 + 2 + vicii.light_pen.x_extra_bits;
        vicii.light_pen.x_extra_bits = 0;
        vicii.light_pen.y = VICII_RASTER_Y(mclk);

        vicii_irq_lightpen_set(mclk);
    }
}

/* Calculate lightpen pulse time based on x/y */
CLOCK vicii_lightpen_timing(int x, int y)
{
    CLOCK pulse_time = maincpu_clk;

    x += 0x80 - vicii.screen_leftborderwidth;
    y += vicii.first_displayed_line;

    /* Check if x would wrap to previous line */
    if (x < 104) {
        /* lightpen is off screen */
        pulse_time = 0;
    } else {
        pulse_time += (x / 8) + (y * vicii.cycles_per_line);
        /* Remove frame alarm jitter */
        pulse_time -= maincpu_clk - VICII_LINE_START_CLK(maincpu_clk);

        /* Store x extra bits for sub CLK precision */
        vicii.light_pen.x_extra_bits = (x >> 1) & 0x3;
    }

    return pulse_time;
}

/* Change the base of RAM seen by the VIC-II.  */
static inline void vicii_set_ram_bases(BYTE *base_p1, BYTE *base_p2)
{
    /* WARNING: assumes `maincpu_rmw_flag' is 0 or 1.  */
    vicii_handle_pending_alarms(maincpu_rmw_flag + 1);

    vicii.ram_base_phi1 = base_p1;
    vicii.ram_base_phi2 = base_p2;
    vicii_update_memory_ptrs(VICII_RASTER_CYCLE(maincpu_clk));
}

void vicii_set_ram_base(BYTE *base)
{
    vicii_set_ram_bases(base, base);
}

void vicii_set_phi1_ram_base(BYTE *base)
{
    vicii_set_ram_bases(base, vicii.ram_base_phi2);
}

void vicii_set_phi2_ram_base(BYTE *base)
{
    vicii_set_ram_bases(vicii.ram_base_phi1, base);
}


void vicii_update_memory_ptrs_external(void)
{
    if (vicii.initialized > 0) {
        vicii_update_memory_ptrs(VICII_RASTER_CYCLE(maincpu_clk));
    }
}

/* Set the memory pointers according to the values in the registers.  */
void vicii_update_memory_ptrs(unsigned int cycle)
{
    /* FIXME: This is *horrible*!  */
    static BYTE *old_screen_ptr, *old_bitmap_low_ptr, *old_bitmap_high_ptr;
    static BYTE *old_chargen_ptr;
    static int old_vbank_p1 = -1;
    static int old_vbank_p2 = -1;
    WORD screen_addr;             /* Screen start address.  */
    BYTE *char_base;              /* Pointer to character memory.  */
    BYTE *bitmap_low_base;        /* Pointer to bitmap memory (low part).  */
    BYTE *bitmap_high_base;       /* Pointer to bitmap memory (high part).  */
    int tmp, bitmap_bank;

    screen_addr = vicii.vbank_phi2 + ((vicii.regs[0x18] & 0xf0) << 6);

    screen_addr = (screen_addr & vicii.vaddr_mask_phi2)
                  | vicii.vaddr_offset_phi2;

    VICII_DEBUG_REGISTER(("Screen memory at $%04X", screen_addr));

    tmp = (vicii.regs[0x18] & 0xe) << 10;
    tmp = (tmp + vicii.vbank_phi1);
    tmp &= vicii.vaddr_mask_phi1;
    tmp |= vicii.vaddr_offset_phi1;

    bitmap_bank = tmp & 0xe000;
    bitmap_low_base = vicii.ram_base_phi1 + bitmap_bank;

    VICII_DEBUG_REGISTER(("Bitmap memory at $%04X", tmp & 0xe000));

    if (cart_ultimax_phi2 != 0) {
        if ((screen_addr & 0x3fff) >= 0x3000)
            vicii.screen_base_phi2 = romh_banks + (romh_bank << 13)
                                     + (screen_addr & 0xfff) + 0x1000;
        else
            vicii.screen_base_phi2 = vicii.ram_base_phi2 + screen_addr;
    } else {
        if ((screen_addr & vicii.vaddr_chargen_mask_phi2)
            != vicii.vaddr_chargen_value_phi2)
            vicii.screen_base_phi2 = vicii.ram_base_phi2 + screen_addr;
        else
            vicii.screen_base_phi2 = mem_chargen_rom_ptr
                                     + (screen_addr & 0xc00);
    }

    if (cart_ultimax_phi1 != 0) {
        if ((screen_addr & 0x3fff) >= 0x3000)
            vicii.screen_base_phi1 = romh_banks + (romh_bank << 13)
                                     + (screen_addr & 0xfff) + 0x1000;
        else
            vicii.screen_base_phi1 = vicii.ram_base_phi1 + screen_addr;

        if ((tmp & 0x3fff) >= 0x3000)
            char_base = romh_banks + (romh_bank << 13) + (tmp & 0xfff) + 0x1000;
        else
            char_base = vicii.ram_base_phi1 + tmp;

        if (((bitmap_bank + 0x1000) & 0x3fff) >= 0x3000)
            bitmap_high_base = romh_banks + (romh_bank << 13) + 0x1000;
        else
            bitmap_high_base = bitmap_low_base + 0x1000;

    } else {
        if ((screen_addr & vicii.vaddr_chargen_mask_phi1)
            != vicii.vaddr_chargen_value_phi1)
            vicii.screen_base_phi1 = vicii.ram_base_phi1 + screen_addr;
        else
            vicii.screen_base_phi1 = mem_chargen_rom_ptr
                                     + (screen_addr & 0xc00);

        if ((tmp & vicii.vaddr_chargen_mask_phi1)
            != vicii.vaddr_chargen_value_phi1)
            char_base = vicii.ram_base_phi1 + tmp;
        else
            char_base = mem_chargen_rom_ptr + (tmp & 0x0800);

        if (((bitmap_bank + 0x1000) & vicii.vaddr_chargen_mask_phi1)
            != vicii.vaddr_chargen_value_phi1)
            bitmap_high_base = bitmap_low_base + 0x1000;
        else
            bitmap_high_base = mem_chargen_rom_ptr;
    }

    tmp = VICII_RASTER_CHAR(cycle);

    if (tmp <= 0 /*&& maincpu_clk < vicii.draw_clk*/) {
        old_screen_ptr = vicii.screen_ptr = vicii.screen_base_phi2;
        old_bitmap_low_ptr = vicii.bitmap_low_ptr = bitmap_low_base;
        old_bitmap_high_ptr = vicii.bitmap_high_ptr = bitmap_high_base;
        old_chargen_ptr = vicii.chargen_ptr = char_base;
        old_vbank_p1 = vicii.vbank_phi1;
        old_vbank_p2 = vicii.vbank_phi2;
        /* vicii.vbank_ptr = vicii.ram_base + vicii.vbank; */
    } else if (tmp < VICII_SCREEN_TEXTCOLS) {
        if (vicii.screen_base_phi2 != old_screen_ptr) {
            raster_changes_foreground_add_ptr(&vicii.raster, tmp,
                                              (void *)&vicii.screen_ptr,
                                              (void *)vicii.screen_base_phi2);
            old_screen_ptr = vicii.screen_base_phi2;
        }

        if (bitmap_low_base != old_bitmap_low_ptr) {
            raster_changes_foreground_add_ptr(&vicii.raster,
                                              tmp,
                                              (void *)&vicii.bitmap_low_ptr,
                                              (void *)(bitmap_low_base));
            old_bitmap_low_ptr = bitmap_low_base;
        }

        if (bitmap_high_base != old_bitmap_high_ptr) {
            raster_changes_foreground_add_ptr(&vicii.raster,
                                              tmp,
                                              (void *)&vicii.bitmap_high_ptr,
                                              (void *)(bitmap_high_base));
            old_bitmap_high_ptr = bitmap_high_base;
        }

        if (char_base != old_chargen_ptr) {
            raster_changes_foreground_add_ptr(&vicii.raster,
                                              tmp,
                                              (void *)&vicii.chargen_ptr,
                                              (void *)char_base);
            old_chargen_ptr = char_base;
        }

        if (vicii.vbank_phi1 != old_vbank_p1) {
            old_vbank_p1 = vicii.vbank_phi1;
        }

        if (vicii.vbank_phi2 != old_vbank_p2) {
            old_vbank_p2 = vicii.vbank_phi2;
        }
    } else {
        if (vicii.screen_base_phi2 != old_screen_ptr) {
            raster_changes_next_line_add_ptr(&vicii.raster,
                                             (void *)&vicii.screen_ptr,
                                             (void *)vicii.screen_base_phi2);
            old_screen_ptr = vicii.screen_base_phi2;
        }

        if (bitmap_low_base != old_bitmap_low_ptr) {
            raster_changes_next_line_add_ptr(&vicii.raster,
                                             (void *)&vicii.bitmap_low_ptr,
                                             (void *)(bitmap_low_base));
            old_bitmap_low_ptr = bitmap_low_base;
        }

        if (bitmap_high_base != old_bitmap_high_ptr) {
            raster_changes_next_line_add_ptr(&vicii.raster,
                                             (void *)&vicii.bitmap_high_ptr,
                                             (void *)(bitmap_high_base));
            old_bitmap_high_ptr = bitmap_high_base;
        }

        if (char_base != old_chargen_ptr) {
            raster_changes_next_line_add_ptr(&vicii.raster,
                                             (void *)&vicii.chargen_ptr,
                                             (void *)char_base);
            old_chargen_ptr = char_base;
        }

        if (vicii.vbank_phi1 != old_vbank_p1) {
            old_vbank_p1 = vicii.vbank_phi1;
        }

        if (vicii.vbank_phi2 != old_vbank_p2) {
            old_vbank_p2 = vicii.vbank_phi2;
        }
    }
}

/* Set the video mode according to the values in registers $D011 and $D016 of
   the VIC-II chip.  */
void vicii_update_video_mode(unsigned int cycle)
{
    int new_video_mode;

    new_video_mode = ((vicii.regs[0x11] & 0x60)
                     | (vicii.regs[0x16] & 0x10)) >> 4;

    if (new_video_mode != vicii.video_mode) {
        switch (new_video_mode) {
          case VICII_ILLEGAL_TEXT_MODE:
          case VICII_ILLEGAL_BITMAP_MODE_1:
          case VICII_ILLEGAL_BITMAP_MODE_2:
            /* Force the overscan color to black.  */
            raster_changes_background_add_int
                (&vicii.raster, VICII_RASTER_X(cycle),
                &vicii.raster.idle_background_color, 0);
            raster_changes_background_add_int
                (&vicii.raster,
                VICII_RASTER_X(VICII_RASTER_CYCLE(maincpu_clk)),
                &vicii.raster.xsmooth_color, 0);
            vicii.get_background_from_vbuf = 0;
            vicii.force_black_overscan_background_color = 1;
            break;
          case VICII_HIRES_BITMAP_MODE:
            raster_changes_background_add_int
                (&vicii.raster, VICII_RASTER_X(cycle),
                &vicii.raster.idle_background_color, 0);
            raster_changes_background_add_int
                (&vicii.raster,
                VICII_RASTER_X(VICII_RASTER_CYCLE(maincpu_clk)),
                &vicii.raster.xsmooth_color,
                vicii.background_color_source & 0x0f);
            vicii.get_background_from_vbuf = VICII_HIRES_BITMAP_MODE;
            vicii.force_black_overscan_background_color = 1;
            break;
          case VICII_EXTENDED_TEXT_MODE:
            raster_changes_background_add_int
                (&vicii.raster, VICII_RASTER_X(cycle),
                &vicii.raster.idle_background_color,
                vicii.regs[0x21]);
            raster_changes_background_add_int
                (&vicii.raster,
                VICII_RASTER_X(VICII_RASTER_CYCLE(maincpu_clk)),
                &vicii.raster.xsmooth_color,
                vicii.regs[0x21 + (vicii.background_color_source >> 6)]);
            vicii.get_background_from_vbuf = VICII_EXTENDED_TEXT_MODE;
            vicii.force_black_overscan_background_color = 0;
            break;
          default:
            /* The overscan background color is given by the background
               color register.  */
            raster_changes_background_add_int
                (&vicii.raster, VICII_RASTER_X(cycle),
                &vicii.raster.idle_background_color,
                vicii.regs[0x21]);
            raster_changes_background_add_int
                (&vicii.raster,
                VICII_RASTER_X(VICII_RASTER_CYCLE(maincpu_clk)),
                &vicii.raster.xsmooth_color,
                vicii.regs[0x21]);
            vicii.get_background_from_vbuf = 0;
            vicii.force_black_overscan_background_color = 0;
            break;
        }

        {
            int pos;

            pos = VICII_RASTER_CHAR(cycle) - 1;

            raster_changes_background_add_int(&vicii.raster,
                                              VICII_RASTER_X(cycle),
                                              &vicii.raster.video_mode,
                                              new_video_mode);

            raster_changes_foreground_add_int(&vicii.raster, pos,
                                              &vicii.raster.last_video_mode,
                                              vicii.video_mode);

            raster_changes_foreground_add_int(&vicii.raster, pos,
                                              &vicii.raster.video_mode,
                                              new_video_mode);

            raster_changes_foreground_add_int(&vicii.raster, pos + 2,
                                              &vicii.raster.last_video_mode,
                                              -1);

        }

        vicii.video_mode = new_video_mode;
    }

#ifdef VICII_VMODE_DEBUG
    switch (new_video_mode) {
      case VICII_NORMAL_TEXT_MODE:
        VICII_DEBUG_VMODE(("Standard Text"));
        break;
      case VICII_MULTICOLOR_TEXT_MODE:
        VICII_DEBUG_VMODE(("Multicolor Text"));
        break;
      case VICII_HIRES_BITMAP_MODE:
        VICII_DEBUG_VMODE(("Hires Bitmap"));
        break;
      case VICII_MULTICOLOR_BITMAP_MODE:
        VICII_DEBUG_VMODE(("Multicolor Bitmap"));
        break;
      case VICII_EXTENDED_TEXT_MODE:
        VICII_DEBUG_VMODE(("Extended Text"));
        break;
      case VICII_ILLEGAL_TEXT_MODE:
        VICII_DEBUG_VMODE(("Illegal Text"));
        break;
      case VICII_ILLEGAL_BITMAP_MODE_1:
        VICII_DEBUG_VMODE(("Invalid Bitmap"));
        break;
      case VICII_ILLEGAL_BITMAP_MODE_2:
        VICII_DEBUG_VMODE(("Invalid Bitmap"));
        break;
      default:                    /* cannot happen */
        VICII_DEBUG_VMODE(("???"));
    }

    VICII_DEBUG_VMODE(("Mode enabled at line $%04X, cycle %d.",
                       VICII_RASTER_Y(maincpu_clk), cycle));
#endif
}

/* Redraw the current raster line.  This happens at cycle VICII_DRAW_CYCLE
   of each line.  */
void vicii_raster_draw_alarm_handler(CLOCK offset, void *data)
{
    BYTE prev_sprite_sprite_collisions;
    BYTE prev_sprite_background_collisions;
    int in_visible_area;

    prev_sprite_sprite_collisions = vicii.sprite_sprite_collisions;
    prev_sprite_background_collisions = vicii.sprite_background_collisions;

    in_visible_area = (vicii.raster.current_line
                      >= (unsigned int)vicii.first_displayed_line
                      && vicii.raster.current_line
                      <= (unsigned int)vicii.last_displayed_line);

    /* handle wrap if the first few lines are displayed in the visible lower border */
    if ((unsigned int)vicii.last_displayed_line >= vicii.screen_height) {
        in_visible_area |= vicii.raster.current_line
                          <= ((unsigned int)vicii.last_displayed_line - vicii.screen_height);
    }

    vicii.raster.xsmooth_shift_left = 0;

    vicii_sprites_reset_xshift();

    raster_line_emulate(&vicii.raster);

#if 0
    if (vicii.raster.current_line >= 60 && vicii.raster.current_line <= 60) {
        char buf[1000];
        int j, i;
        for (i = 0; i < 8; i++) {
            memset(buf, 0, sizeof(buf));
            for (j = 0; j < 40; j++)
            sprintf(&buf[strlen(buf)], "%02x",
                    vicii.raster.draw_buffer_ptr[vicii.raster.xsmooth
                    + vicii.raster.geometry->gfx_position.x + i * 40 + j]);
            log_debug(buf);
        } 
    }
#endif

    if (vicii.raster.current_line == 0) {
        /* no vsync here for NTSC  */
        if ((unsigned int)vicii.last_displayed_line < vicii.screen_height) {
            raster_skip_frame(&vicii.raster,
                              vsync_do_vsync(vicii.raster.canvas,
                              vicii.raster.skip_frame));
        }
        vicii.memptr = 0;
        vicii.mem_counter = 0;
        vicii.light_pen.triggered = 0;
        vicii.raster.blank_off = 0;

#ifdef __MSDOS__
        if ((unsigned int)vicii.last_displayed_line < vicii.screen_height) {
            if (vicii.raster.canvas->draw_buffer->canvas_width
                <= VICII_SCREEN_XPIX
                && vicii.raster.canvas->draw_buffer->canvas_height
                <= VICII_SCREEN_YPIX
                && vicii.raster.canvas->viewport->update_canvas)
                canvas_set_border_color(vicii.raster.canvas,
                                        vicii.raster.border_color);
        }
#endif
    }

    /* vsync for NTSC */
    if ((unsigned int)vicii.last_displayed_line >= vicii.screen_height
        && vicii.raster.current_line == vicii.last_displayed_line - vicii.screen_height + 1) {
        raster_skip_frame(&vicii.raster,
                          vsync_do_vsync(vicii.raster.canvas,
                          vicii.raster.skip_frame));
#ifdef __MSDOS__
        if (vicii.raster.canvas->draw_buffer->canvas_width
            <= VICII_SCREEN_XPIX
            && vicii.raster.canvas->draw_buffer->canvas_height
            <= VICII_SCREEN_YPIX
            && vicii.raster.canvas->viewport->update_canvas)
            canvas_set_border_color(vicii.raster.canvas,
                                    vicii.raster.border_color);
#endif
    }

    if (in_visible_area) {
        vicii.raster.draw_idle_state = vicii.idle_state;
        vicii.bad_line = 0;
    }

    vicii.buf_offset = 0;

    if (vicii.raster.current_line == vicii.first_dma_line) {
        vicii.allow_bad_lines = !vicii.raster.blank;
    }

    /* As explained in Christian's article, only the first collision
       (i.e. the first time the collision register becomes non-zero) actually
       triggers an interrupt.  */
    if (vicii_resources.sprite_sprite_collisions_enabled
        && vicii.raster.sprite_status->sprite_sprite_collisions != 0
        && !prev_sprite_sprite_collisions) {
        vicii_irq_sscoll_set();
    }

    if (vicii_resources.sprite_background_collisions_enabled
        && vicii.raster.sprite_status->sprite_background_collisions
        && !prev_sprite_background_collisions) {
        vicii_irq_sbcoll_set();
    }
}

void vicii_set_canvas_refresh(int enable)
{
    raster_set_canvas_refresh(&vicii.raster, enable);
}

void vicii_shutdown(void)
{
    vicii_sprites_shutdown();
    raster_sprite_status_destroy(&vicii.raster);
    raster_shutdown(&vicii.raster);
}

void vicii_screenshot(screenshot_t *screenshot)
{
    raster_screenshot(&vicii.raster, screenshot);
}

void vicii_async_refresh(struct canvas_refresh_s *refresh)
{
    raster_async_refresh(&vicii.raster, refresh);
}

