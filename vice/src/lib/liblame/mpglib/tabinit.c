/*
 * tabinit.c
 *
 * Copyright (C) 1999-2010 The L.A.M.E. project
 *
 * Initially written by Michael Hipp, see also AUTHORS and README.
 *  
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
/* $Id: tabinit.c,v 1.16 2010/03/22 14:30:19 robert Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include "tabinit.h"
#include "mpg123.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif

real    decwin[512 + 32];
static real cos64[16], cos32[8], cos16[4], cos8[2], cos4[1];
real   *pnts[] = { cos64, cos32, cos16, cos8, cos4 };

/* *INDENT-OFF* */

static const double dewin[512] = {
   0.000000000,-0.000015259,-0.000015259,-0.000015259,
  -0.000015259,-0.000015259,-0.000015259,-0.000030518,
  -0.000030518,-0.000030518,-0.000030518,-0.000045776,
  -0.000045776,-0.000061035,-0.000061035,-0.000076294,
  -0.000076294,-0.000091553,-0.000106812,-0.000106812,
  -0.000122070,-0.000137329,-0.000152588,-0.000167847,
  -0.000198364,-0.000213623,-0.000244141,-0.000259399,
  -0.000289917,-0.000320435,-0.000366211,-0.000396729,
  -0.000442505,-0.000473022,-0.000534058,-0.000579834,
  -0.000625610,-0.000686646,-0.000747681,-0.000808716,
  -0.000885010,-0.000961304,-0.001037598,-0.001113892,
  -0.001205444,-0.001296997,-0.001388550,-0.001480103,
  -0.001586914,-0.001693726,-0.001785278,-0.001907349,
  -0.002014160,-0.002120972,-0.002243042,-0.002349854,
  -0.002456665,-0.002578735,-0.002685547,-0.002792358,
  -0.002899170,-0.002990723,-0.003082275,-0.003173828,
  -0.003250122,-0.003326416,-0.003387451,-0.003433228,
  -0.003463745,-0.003479004,-0.003479004,-0.003463745,
  -0.003417969,-0.003372192,-0.003280640,-0.003173828,
  -0.003051758,-0.002883911,-0.002700806,-0.002487183,
  -0.002227783,-0.001937866,-0.001617432,-0.001266479,
  -0.000869751,-0.000442505, 0.000030518, 0.000549316,
   0.001098633, 0.001693726, 0.002334595, 0.003005981,
   0.003723145, 0.004486084, 0.005294800, 0.006118774,
   0.007003784, 0.007919312, 0.008865356, 0.009841919,
   0.010848999, 0.011886597, 0.012939453, 0.014022827,
   0.015121460, 0.016235352, 0.017349243, 0.018463135,
   0.019577026, 0.020690918, 0.021789551, 0.022857666,
   0.023910522, 0.024932861, 0.025909424, 0.026840210,
   0.027725220, 0.028533936, 0.029281616, 0.029937744,
   0.030532837, 0.031005859, 0.031387329, 0.031661987,
   0.031814575, 0.031845093, 0.031738281, 0.031478882,
   0.031082153, 0.030517578, 0.029785156, 0.028884888,
   0.027801514, 0.026535034, 0.025085449, 0.023422241,
   0.021575928, 0.019531250, 0.017257690, 0.014801025,
   0.012115479, 0.009231567, 0.006134033, 0.002822876,
  -0.000686646,-0.004394531,-0.008316040,-0.012420654,
  -0.016708374,-0.021179199,-0.025817871,-0.030609131,
  -0.035552979,-0.040634155,-0.045837402,-0.051132202,
  -0.056533813,-0.061996460,-0.067520142,-0.073059082,
  -0.078628540,-0.084182739,-0.089706421,-0.095169067,
  -0.100540161,-0.105819702,-0.110946655,-0.115921021,
  -0.120697021,-0.125259399,-0.129562378,-0.133590698,
  -0.137298584,-0.140670776,-0.143676758,-0.146255493,
  -0.148422241,-0.150115967,-0.151306152,-0.151962280,
  -0.152069092,-0.151596069,-0.150497437,-0.148773193,
  -0.146362305,-0.143264771,-0.139450073,-0.134887695,
  -0.129577637,-0.123474121,-0.116577148,-0.108856201,
  -0.100311279,-0.090927124,-0.080688477,-0.069595337,
  -0.057617187,-0.044784546,-0.031082153,-0.016510010,
  -0.001068115, 0.015228271, 0.032379150, 0.050354004,
   0.069168091, 0.088775635, 0.109161377, 0.130310059,
   0.152206421, 0.174789429, 0.198059082, 0.221984863,
   0.246505737, 0.271591187, 0.297210693, 0.323318481,
   0.349868774, 0.376800537, 0.404083252, 0.431655884,
   0.459472656, 0.487472534, 0.515609741, 0.543823242,
   0.572036743, 0.600219727, 0.628295898, 0.656219482,
   0.683914185, 0.711318970, 0.738372803, 0.765029907,
   0.791213989, 0.816864014, 0.841949463, 0.866363525,
   0.890090942, 0.913055420, 0.935195923, 0.956481934,
   0.976852417, 0.996246338, 1.014617920, 1.031936646,
   1.048156738, 1.063217163, 1.077117920, 1.089782715,
   1.101211548, 1.111373901, 1.120223999, 1.127746582,
   1.133926392, 1.138763428, 1.142211914, 1.144287109,
   1.144989014
};
/* *INDENT-ON* */

void
make_decode_tables(long scaleval)
{
    int     i, j, k, kr, divv;
    real   *table, *costab;


    for (i = 0; i < 5; i++) {
        kr = 0x10 >> i;
        divv = 0x40 >> i;
        costab = pnts[i];
        for (k = 0; k < kr; k++)
            costab[k] = (real) (1.0 / (2.0 * cos(M_PI * ((double) k * 2.0 + 1.0) / (double) divv)));
    }

    table = decwin;
    scaleval = -scaleval;
    for (i = 0, j = 0; i < 256; i++, j++, table += 32) {
        if (table < decwin + 512 + 16)
            table[16] = table[0] = (real) (dewin[j] * scaleval);
        if (i % 32 == 31)
            table -= 1023;
        if (i % 64 == 63)
            scaleval = -scaleval;
    }

    for ( /* i=256 */ ; i < 512; i++, j--, table += 32) {
        if (table < decwin + 512 + 16)
            table[16] = table[0] = (real) (dewin[j] * scaleval);
        if (i % 32 == 31)
            table -= 1023;
        if (i % 64 == 63)
            scaleval = -scaleval;
    }
}
