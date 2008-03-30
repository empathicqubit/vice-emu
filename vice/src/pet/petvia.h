/*
 * petvia.h - PET VIA emulation.
 *
 * Written by
 *  Andr� Fachat <fachat@physik.tu-chemnitz.de>
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

#ifndef _PETVIA_H
#define _PETVIA_H

#include "types.h"

struct machine_context_s;
struct snapshot_s;
struct via_context_s;

extern void petvia_setup_context(struct machine_context_s *machine_context);
extern void via_reset(struct via_context_s *via_context);
extern void via_init(struct via_context_s *via_context);
extern void via_signal(struct via_context_s *via_context, int line, int edge);
extern BYTE REGPARM1 via_read(WORD addr);
extern BYTE REGPARM1 via_peek(WORD addr);
extern void REGPARM2 via_store(WORD addr, BYTE value);

extern int via_snapshot_read_module(struct via_context_s *via_context,
                                    struct snapshot_s *s);
extern int via_snapshot_write_module(struct via_context_s *via_context,
                                     struct snapshot_s *s);

#endif

