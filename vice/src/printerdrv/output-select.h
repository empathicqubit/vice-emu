/*
 * output-select.h - Select an output driver.
 *
 * Written by
 *  Andreas Boose <boose@linux.rz.fh-hannover.de>
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

#ifndef _OUTPUT_SELECT_H
#define _OUTPUT_SELECT_H

#include "types.h"

struct output_select_s {
    const char *output_name;
    int (*output_open)(unsigned int prnr);
    void (*output_close)(unsigned int prnr);
    int (*output_putc)(unsigned int prnr, BYTE b);
    int (*output_getc)(unsigned int prnr, BYTE *b);
    int (*output_flush)(unsigned int prnr);
};
typedef struct output_select_s output_select_t;

extern void output_select_init(void);
extern int output_select_init_resources(void);
extern int output_select_init_cmdline_options(void);

extern void output_select_register(output_select_t *output_select);

extern int output_select_open(unsigned int prnr);
extern void output_select_close(unsigned int prnr);
extern int output_select_putc(unsigned int prnr, BYTE b);
extern int output_select_getc(unsigned int prnr, BYTE *b);
extern int output_select_flush(unsigned int prnr);

#endif

