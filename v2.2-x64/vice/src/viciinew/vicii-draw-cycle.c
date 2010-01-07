/*
 * vicii-draw-cycle.c - Cycle based rendering for the VIC-II emulation.
 *
 * Written by
 *  Daniel Kahlin <daniel@kahlin.net>
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

#include "types.h"
#include "vicii-draw-cycle.h"
#include "viciitypes.h"

/* disable for debugging */
#define DRAW_INLINE inline

/* foreground/background graphics */

BYTE gbuf_pipe0_reg = 0;
BYTE cbuf_pipe0_reg = 0;
BYTE vbuf_pipe0_reg = 0;
BYTE gbuf_pipe1_reg = 0;
BYTE cbuf_pipe1_reg = 0;
BYTE vbuf_pipe1_reg = 0;

BYTE xscroll_pipe = 0;
BYTE vmode_pipe = 0;

/* gbuf shift register */
BYTE gbuf_reg = 0;
BYTE gbuf_mc_flop = 0;
BYTE gbuf_pixel_reg = 0;

/* cbuf and vbuf registers */
BYTE cbuf_reg = 0;
BYTE vbuf_reg = 0;

BYTE last_pixel_color = 0;

BYTE idle_state = 0;

/* sprites */

BYTE sprite_pending_bits = 0;
BYTE sprite_active_bits = 0;

/* sbuf shift registers */
#if 0
DWORD sbuf_reg[8]; /* maybe use those directly present in vicii.*? */
#endif
BYTE sbuf_pixel_reg[8];
BYTE sbuf_expx_flop[8];
BYTE sbuf_mc_flop[8];

/* border */
BYTE bbuf_reg = 0;
int main_border_pipe = 0;


static DRAW_INLINE void draw_sprites(int xpos, int j, int pri, int bp)
{
    int s;
    BYTE c[4];
    int rendered;
    BYTE collision_mask;
    int collision_count;
    int x;

    /* do nothing if all sprites are disabled */
    if (!vicii.sprite_display_bits) {
        return;
    }

    c[1] = vicii.regs[0x25];
    c[3] = vicii.regs[0x26];

    rendered = 0;
    collision_mask = 0;
    collision_count = 0;
    for (s = 0; s < 8; s++) {

        if ( vicii.sprite_display_bits & (1<<s) ) {

            /* start rendering on position match */
            if ( sprite_pending_bits & (1 << s) ) {
                if ( xpos == vicii.sprite[s].x ) {
                    sbuf_expx_flop[s] = 0;
                    sbuf_mc_flop[s] = 0;
                    sprite_active_bits |= (1 << s);
                    sprite_pending_bits &= ~(1 << s);
                }
            }

            if ( sprite_active_bits & (1 << s) ) {
                int spri = vicii.regs[0x1b] & (1 << s);
                int mc = vicii.regs[0x1c] & (1 << s);
                int expx = vicii.regs[0x1d] & (1 << s);
                c[2] = vicii.regs[0x27 + s];

                /* render pixels if shift register or pixel reg still contains data */
                if ( vicii.sprite[s].data || sbuf_pixel_reg[s] ) {
                    
                    if ( sbuf_expx_flop[s] == 0 ) {
                        if (mc) {
                            if (sbuf_mc_flop[s] == 0) {
                                /* fetch 2 bits */
                                sbuf_pixel_reg[s] = (vicii.sprite[s].data >> 22) & 0x03;
                            }
                            sbuf_mc_flop[s] = ~sbuf_mc_flop[s];
                        } else {
                            /* fetch 1 bit and make it 0 or 2 */
                            sbuf_pixel_reg[s] = ( (vicii.sprite[s].data >> 23) & 0x01 ) << 1;
                        }
                    }

                    /*
                     * render pixels unless a higher priority sprite has already
                     * rendered pixels.
                     */
                    if (sbuf_pixel_reg[s]) {
                        if (!rendered) {
                            if ( !(pri && spri) ) {
                                vicii.dbuf[j] = c[ sbuf_pixel_reg[s] ];
                            }
                            rendered = 1;
                        }
                        collision_mask |= (1 << s);
                        collision_count++;
                    }

                    /* shift the sprite buffer and handle expansion flags */
                    if (sbuf_expx_flop[s] == 0) {
                        vicii.sprite[s].data <<= 1;
                    }
                    if (expx) {
                        sbuf_expx_flop[s] = ~sbuf_expx_flop[s];
                    }
                } else {
                    sprite_active_bits &= ~(1 << s);
                }
            }
        }
    }
    
    if (!bp) {
        /* only flag collisions when not in the border area */
        if (collision_count > 1) {
            vicii.sprite_sprite_collisions |= collision_mask;
        }
        if (pri) {
            vicii.sprite_background_collisions |= collision_mask;
        }
    }
}

void vicii_draw_cycle(void)
{
    int cycle, offs, i;
    int xpos;
    cycle = vicii.raster_cycle;

    /* convert cycle to an x-position. */
    if (cycle < 13) {
        xpos = cycle * 8 + 0x190;
    } else if (cycle < 54) {
        xpos = (cycle - 13) * 8;
    } else {
        xpos = (cycle - 15) * 8;
    }

    /* reset rendering on raster cycle 0 */
    if (cycle == 0) {
        vicii.dbuf_offset = 0;
    }

    /* this is replicated a bit from vicii-cycle.c */
    switch (cycle) {
    case 58:
        sprite_pending_bits |= (1<<0);
        break;
    case 60:
        sprite_pending_bits |= (1<<1);
        break;
    case 62:
        sprite_pending_bits |= (1<<2);
        break;
    case 64:
        sprite_pending_bits |= (1<<3);
        break;
    case 1:
        sprite_pending_bits |= (1<<4);
        break;
    case 3:
        sprite_pending_bits |= (1<<5);
        break;
    case 5:
        sprite_pending_bits |= (1<<6);
        break;
    case 7:
        sprite_pending_bits |= (1<<7);
        break;
    }

    offs = vicii.dbuf_offset;
    /* guard */
    if (offs >= VICII_DRAW_BUFFER_SIZE) 
        return;

    {
        BYTE bg, rsel;
        bg = vicii.regs[0x21];
        rsel = vicii.regs[0x16] & 0x8;

        /* render pixels */
        for (i = 0; i < 8; i++) {
            int j = i + offs;
            BYTE px;
            BYTE bp;
            BYTE c[4];
            int pri;
           
            /* Load new gbuf/vbuf/cbuf values at offset == xscroll */
            if (i == xscroll_pipe) {
                /* latch values at time xs */
                vbuf_reg = vbuf_pipe1_reg;
                cbuf_reg = cbuf_pipe1_reg;
                gbuf_reg = gbuf_pipe1_reg;
                gbuf_mc_flop = 0;
            }
           
            /* Load new border mask depending on rsel and xscroll */
            if (rsel) {
                if (i == 0 && main_border_pipe) {
                    bbuf_reg = 0xff;
                }
            } else {
                if (i == 7 && vicii.main_border) {
                    bbuf_reg = 0xff;
                }
            }



            c[0] = bg;


            /* setup colors and read pixels depending on video mode */
            switch (vmode_pipe) {

            case VICII_NORMAL_TEXT_MODE:
                c[3] = cbuf_reg;

                px = (gbuf_reg & 0x80) ? 3 : 0;
                break;

            case VICII_MULTICOLOR_TEXT_MODE:
                c[1] = vicii.ext_background_color[0];
                c[2] = vicii.ext_background_color[1];
                c[3] = cbuf_reg & 0x07;
                if (cbuf_reg & 0x08) {
                    /* mc pixels */
                    if (gbuf_mc_flop == 0) {
                        gbuf_pixel_reg = gbuf_reg >> 6;
                    }
                    px = gbuf_pixel_reg;
                } else {
                    /* hires pixels */
                    px = (gbuf_reg & 0x80) ? 3 : 0;
                }
                break;

            case VICII_HIRES_BITMAP_MODE:
                c[0] = vbuf_reg & 0x0f;
                c[3] = vbuf_reg >> 4;
                px = (gbuf_reg & 0x80) ? 3 : 0;
                break;

            case VICII_MULTICOLOR_BITMAP_MODE:
                c[1] = vbuf_reg >> 4;
                c[2] = vbuf_reg & 0x0f;
                c[3] = cbuf_reg;
                if (gbuf_mc_flop == 0) {
                    gbuf_pixel_reg = gbuf_reg >> 6;
                }
                px = gbuf_pixel_reg;
                break;
            
            case VICII_EXTENDED_TEXT_MODE:
                c[3] = cbuf_reg;

                switch (vbuf_reg & 0xc0) {
                case 0x00:
                    c[0] = bg;
                    break;
                case 0x40:
                    c[0] = vicii.ext_background_color[0];
                    break;
                case 0x80:
                    c[0] = vicii.ext_background_color[1];
                    break;
                case 0xc0:
                    c[0] = vicii.ext_background_color[2];
                    break;
                }

                px = (gbuf_reg & 0x80) ? 3 : 0;
                break;

            case VICII_IDLE_MODE:
                c[3] = 0;

                px = (gbuf_reg & 0x80) ? 3 : 0;
                break;

            case VICII_ILLEGAL_TEXT_MODE:
                c[0] = 0;
                c[1] = 0;
                c[2] = 0;
                c[3] = 0;
                if (cbuf_reg & 0x08) {
                    /* mc pixels */
                    if (gbuf_mc_flop == 0) {
                        gbuf_pixel_reg = gbuf_reg >> 6;
                    }
                    px = gbuf_pixel_reg;
                } else {
                    /* hires pixels */
                    px = (gbuf_reg & 0x80) ? 3 : 0;
                }
                break;

            case VICII_ILLEGAL_BITMAP_MODE_1:
                c[0] = 0;
                c[3] = 0;
                px = (gbuf_reg & 0x80) ? 3 : 0;
                break;

            case VICII_ILLEGAL_BITMAP_MODE_2:
                c[0] = 0;
                c[1] = 0;
                c[2] = 0;
                c[3] = 0;

                /* mc pixels */
                if (gbuf_mc_flop == 0) {
                    gbuf_pixel_reg = gbuf_reg >> 6;
                }
                px = gbuf_pixel_reg;
                break;

            }

            /* Determine pixel color and priority */
            last_pixel_color = c[px];
            pri = (px & 0x2);

            /* shift the graphics buffer */
            gbuf_reg <<= 1;
            gbuf_mc_flop = ~gbuf_mc_flop;
            
            /* Determine border state */
            bp = (bbuf_reg & 0x80) ? 1 : 0;

            /* shift the border buffer */
            bbuf_reg <<= 1;

            /* draw pixel */
            vicii.dbuf[j] = last_pixel_color;

            /* process sprites */
            draw_sprites(xpos+i, j, pri, bp);

            /* draw border on top */
            if (bp) {
                vicii.dbuf[j] = vicii.regs[0x20];
            }
        }

    }

    vicii.dbuf_offset += 8;


    /* shift and put the next data into the pipe. */
    vbuf_pipe1_reg = vbuf_pipe0_reg;
    cbuf_pipe1_reg = cbuf_pipe0_reg;
    gbuf_pipe1_reg = gbuf_pipe0_reg;

    /* are we within the display area? */
    if ( (cycle >= 14 && cycle <= 53) ) {
        vbuf_pipe0_reg = vicii.vbuf[cycle - 14];
        cbuf_pipe0_reg = vicii.cbuf[cycle - 14];
        gbuf_pipe0_reg = vicii.gbuf;
    } else {
        vbuf_pipe0_reg = 0;
        cbuf_pipe0_reg = 0;
        gbuf_pipe0_reg = 0;
    }
    main_border_pipe = vicii.main_border;

    /*
     * force VICII_IDLE_MODE if we are in idle state
     * Why is VICII_IDLE_MODE a real mode? Should be checked!
     */
    if (vicii.idle_state) {
        vmode_pipe = VICII_IDLE_MODE;
    } else {
        vmode_pipe = vicii.video_mode;
    }
    xscroll_pipe = vicii.regs[0x16] & 0x07;

}


void vicii_draw_cycle_init(void)
{
    memset(vicii.dbuf, 0, VICII_DRAW_BUFFER_SIZE);
    vicii.dbuf_offset = 0;
}

