/*
 *      lame_intrin.h include file
 *
 *      Copyright (c) 2006 Gabriel Bouvigne
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */


#ifndef LAME_INTRIN_H
#define LAME_INTRIN_H


void
init_xrpow_core_sse(gr_info * const cod_info, FLOAT xrpow[576], int upper, FLOAT * sum);

void
fht_SSE2(FLOAT* , int);

#endif
