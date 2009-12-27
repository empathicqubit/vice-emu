/*
 * vicii-fetch.c - Phi2 data fetch for the VIC-II emulation.
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

#include <string.h>

#include "alarm.h"
#include "debug.h"
#include "dma.h"
#include "log.h"
#include "mainc64cpu.h"
#include "mem.h"
#include "raster-sprite-status.h"
#include "raster-sprite.h"
#include "raster.h"
#include "types.h"
#include "vicii-fetch.h"
#include "vicii-irq.h"
#include "vicii-sprites.h"
#include "viciitypes.h"


/*-----------------------------------------------------------------------*/

inline static void swap_sprite_data_buffers(void)
{
    DWORD *tmp;
    raster_sprite_status_t *sprite_status;

    /* Swap sprite data buffers.  */
    sprite_status = vicii.raster.sprite_status;
    tmp = sprite_status->sprite_data;
    sprite_status->sprite_data = sprite_status->new_sprite_data;
    sprite_status->new_sprite_data = tmp;
    sprite_status->new_dma_msk = sprite_status->dma_msk;
}

/* Enable DMA for sprite `num'.  */
inline static void turn_sprite_dma_on(unsigned int num)
{
    raster_sprite_status_t *sprite_status;
    raster_sprite_t *sprite;

    sprite_status = vicii.raster.sprite_status;
    sprite = sprite_status->sprites + num;

    sprite_status->new_dma_msk |= 1 << num;
    sprite->dma_flag = 1;
    sprite->memptr = 0;
    sprite->exp_flag = sprite->y_expanded ? 0 : 1;
    sprite->memptr_inc = sprite->exp_flag ? 3 : 0;
}

inline static int check_sprite_dma(int i)
{
    return vicii.raster.sprite_status->sprites[i].dma_flag;
}

inline static int sprite_dma_cycle_1(int i)
{
    raster_sprite_status_t *sprite_status;
    BYTE *bank_phi1, *bank_phi2, *spr_base;

    sprite_status = vicii.raster.sprite_status;
    /* FIXME: the 3 byte sprite data is instead taken during a Ph1/Ph2/Ph1
       sequence. This is of minor interest, though, only for CBM-II... */
    bank_phi1 = vicii.ram_base_phi1 + vicii.vbank_phi1;
    bank_phi2 = vicii.ram_base_phi2 + vicii.vbank_phi2;
    spr_base = vicii.screen_base_phi1 + 0x3f8 + i;

    /* Fetch sprite data.  */
    if (check_sprite_dma(i)) {
        BYTE *src_phi1, *src_phi2;
        BYTE *dest;
        int my_memptr;

        src_phi1 = bank_phi1 + (*spr_base << 6);
        src_phi2 = bank_phi2 + (*spr_base << 6);
        my_memptr = sprite_status->sprites[i].memptr;
        dest = (BYTE *)(sprite_status->new_sprite_data + i);

        if (((vicii.vbank_phi1 + (*spr_base << 6))
            & vicii.vaddr_chargen_mask_phi1)
            == vicii.vaddr_chargen_value_phi1) {
            src_phi1 = mem_chargen_rom_ptr + ((*spr_base & 0x3f) << 6);
        }

        if (((vicii.vbank_phi2 + (*spr_base << 6))
            & vicii.vaddr_chargen_mask_phi2)
            == vicii.vaddr_chargen_value_phi2) {
            src_phi2 = mem_chargen_rom_ptr + ((*spr_base & 0x3f) << 6);
        }

        dest[0] = src_phi2[my_memptr];
        dest[1] = src_phi1[++my_memptr & 0x3f];
        dest[2] = src_phi2[++my_memptr & 0x3f];
        return 1;
    }

    return 0;
}

inline static int sprite_dma_cycle_2(int i)
{
    return check_sprite_dma(i) ? 1 : 0;
}

inline static int trigger_sprite_dma(int i)
{
    raster_sprite_status_t *sprite_status;
    raster_sprite_t *sprite;
    const int b = (1 << i);

    sprite_status = vicii.raster.sprite_status;
    sprite = sprite_status->sprites + i;

    if (!sprite_status->visible_msk && !sprite_status->dma_msk) {
        return 0;
    }

    if ((sprite_status->visible_msk & b)
        && sprite->y == ((int)((vicii.raster_line - ((i<4)?0:1)) & 0xff))
        && !sprite->dma_flag) {
        turn_sprite_dma_on(i);
    } else if (sprite->dma_flag) {
        sprite->memptr = (sprite->memptr + sprite->memptr_inc) & 0x3f;

        if (sprite->y_expanded) {
            sprite->exp_flag = !sprite->exp_flag;
        }

        sprite->memptr_inc = sprite->exp_flag ? 3 : 0;

        if (sprite->memptr == 63) {
            sprite->dma_flag = 0;
            sprite_status->new_dma_msk &= ~b;

            if ((sprite_status->visible_msk & b)
                && sprite->y == ((int)vicii.raster.current_line & 0xff)) {
                turn_sprite_dma_on(i);
            }
        }
    }

    return sprite->dma_flag;
}

/*-----------------------------------------------------------------------*/

inline static BYTE gfx_data_illegal_bitmap(unsigned int num)
{
    unsigned int j;

    j = ((vicii.memptr << 3) + vicii.raster.ycounter + num * 8);

    if (j & 0x1000) {
        return vicii.bitmap_high_ptr[j & 0x9ff];
    } else {
        return vicii.bitmap_low_ptr[j & 0x9ff];
    }
}

inline static BYTE gfx_data_hires_bitmap(unsigned int num)
{
    unsigned int j;

    j = ((vicii.memptr << 3) + vicii.raster.ycounter + num * 8);

    if (j & 0x1000) {
        return vicii.bitmap_high_ptr[j & 0xfff];
    } else {
        return vicii.bitmap_low_ptr[j & 0xfff];
    }
}

inline static BYTE gfx_data_extended_text(unsigned int c)
{
    return vicii.chargen_ptr[(c & 0x3f) * 8 + vicii.raster.ycounter];
}

inline static BYTE gfx_data_normal_text(unsigned int c)
{
    return vicii.chargen_ptr[c * 8 + vicii.raster.ycounter];
}

/*-----------------------------------------------------------------------*/

void vicii_fetch_start(void)
{
    raster_t *raster;
    raster = &vicii.raster;

    if ((vicii.raster_line & 7) == (unsigned int)raster->ysmooth
        && vicii.allow_bad_lines
        && vicii.raster_line >= vicii.first_dma_line
        && vicii.raster_line <= vicii.last_dma_line) {

        /*VICII_DEBUG_CYCLE(("fetch start: line %i, clk %i", vicii.raster_line, vicii.raster_cycle));*/

        vicii.fetch_active = 1;

        vicii.mem_counter = vicii.memptr;

        raster->draw_idle_state = 0;
        raster->ycounter = 0;
        vicii.force_display_state = 1;

        vicii.idle_state = 0;
        vicii.idle_data_location = IDLE_NONE;
        vicii.ycounter_reset_checked = 1;
        vicii.memory_fetch_done = 2;
        vicii.bad_line = 1;

        vicii.prefetch_cycles = 3;
        vicii.buf_offset = 0;
        vicii.gbuf_offset = 0;
    }
}

void vicii_fetch_stop(void)
{
    vicii.fetch_active = 0;
    vicii.bad_line = 0;
    vicii.buf_offset = 0;
    vicii.gbuf_offset = 0;
}

int vicii_fetch_matrix(void)
{
    vicii.vbuf[vicii.buf_offset] = vicii.screen_base_phi2[vicii.mem_counter];
    vicii.cbuf[vicii.buf_offset] = mem_color_ram_vicii[vicii.mem_counter];

    vicii.mem_counter++;
    vicii.mem_counter &= 0x3ff;

    return 1;
}

void vicii_fetch_graphics(void)
{
    switch (vicii.raster.video_mode) {
        case VICII_NORMAL_TEXT_MODE:
        case VICII_MULTICOLOR_TEXT_MODE:
            vicii.gbuf[vicii.gbuf_offset] = gfx_data_normal_text(vicii.vbuf[vicii.buf_offset]);
            break;
        case VICII_HIRES_BITMAP_MODE:
        case VICII_MULTICOLOR_BITMAP_MODE:
            vicii.gbuf[vicii.gbuf_offset] = gfx_data_hires_bitmap(vicii.buf_offset);
            break;
        case VICII_EXTENDED_TEXT_MODE:
        case VICII_ILLEGAL_TEXT_MODE:
            vicii.gbuf[vicii.gbuf_offset] = gfx_data_extended_text(vicii.vbuf[vicii.buf_offset]);
            break;
        case VICII_ILLEGAL_BITMAP_MODE_1:
        case VICII_ILLEGAL_BITMAP_MODE_2:
            vicii.gbuf[vicii.gbuf_offset] = gfx_data_illegal_bitmap(vicii.buf_offset);
            break;
        default:
            break;
    }
    vicii.gbuf_offset++;
    vicii.buf_offset++;
}

int vicii_fetch_sprites(int cycle)
{
    int ba_low = 0;

    switch (cycle) {
        case 56: /* sprite 0 trigger */
            swap_sprite_data_buffers();
            vicii_sprites_reset_sprline();
            ba_low = trigger_sprite_dma(0);
            break;
        case 57:
            ba_low = check_sprite_dma(0);
            break;
        case 58: /* sprite 1 trigger */
            ba_low = trigger_sprite_dma(1) | check_sprite_dma(0);
            break;
        case 59: /* sprite 0 pointer */
            ba_low = sprite_dma_cycle_1(0) | check_sprite_dma(1);
            break;
        case 60: /* sprite 0 data / 2 trigger */
            ba_low = sprite_dma_cycle_2(0) | trigger_sprite_dma(2) | check_sprite_dma(1);
            break;
        case 61: /* sprite 1 pointer */
            ba_low = sprite_dma_cycle_1(1) | check_sprite_dma(2);
            break;
        case 62: /* sprite 1 data / 3 trigger */
            ba_low = sprite_dma_cycle_2(1) | trigger_sprite_dma(3) | check_sprite_dma(2);
            break;
        case 63: /* sprite 2 pointer */
            ba_low = sprite_dma_cycle_1(2) | check_sprite_dma(3);
            break;
        case 64: /* sprite 2 data / 4 trigger */
            ba_low = sprite_dma_cycle_2(2) | trigger_sprite_dma(4) | check_sprite_dma(3);
            break;
        case 0: /* sprite 3 pointer */
            ba_low = sprite_dma_cycle_1(3) | check_sprite_dma(4);
            break;
        case 1: /* sprite 3 data / 5 trigger*/
            ba_low = sprite_dma_cycle_2(3) | trigger_sprite_dma(5) | check_sprite_dma(4);
            break;
        case 2: /* sprite 4 pointer */
            ba_low = sprite_dma_cycle_1(4) | check_sprite_dma(5);
            break;
        case 3: /* sprite 4 data / 6 trigger */
            ba_low = sprite_dma_cycle_2(4) | trigger_sprite_dma(6) | check_sprite_dma(5);
            break;
        case 4: /* sprite 5 pointer */
            ba_low = sprite_dma_cycle_1(5) | check_sprite_dma(6);
            break;
        case 5: /* sprite 5 data / 7 trigger */
            ba_low = sprite_dma_cycle_2(5) | trigger_sprite_dma(7) | check_sprite_dma(6);
            break;
        case 6: /* sprite 6 pointer */
            ba_low = sprite_dma_cycle_1(6) | check_sprite_dma(7);
            break;
        case 7: /* sprite 6 data */
            ba_low = sprite_dma_cycle_2(6) | check_sprite_dma(7);
            break;
        case 8: /* sprite 7 pointer */
            ba_low = sprite_dma_cycle_1(7);
            break;
        case 9: /* sprite 7 data */
            ba_low = sprite_dma_cycle_2(7);
            break;
        default:
            break;
    }

    return ba_low;
}
