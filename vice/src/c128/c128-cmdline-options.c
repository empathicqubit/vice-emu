/** \file   c128-cmdline-options.c
 * \brief   C128 command line options
 *
 * \author  Andreas Boose <viceteam@t-online.de>
 * \author  Marco van den Heuvel <blackystardust68@yahoo.com
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
#include <stdlib.h>
#include <string.h>

#include "c128-cmdline-options.h"
#include "c128-resources.h"
#include "c128model.h"
#include "cmdline.h"
#include "machine.h"
#include "translate.h"

static int set_cia_model(const char *value, void *extra_param)
{
    int model;

    model = atoi(value);
    c128_resources_update_cia_models(model);

    return 0;
}

struct model_s {
    const char *name;
    int model;
};

static struct model_s model_match[] = {
    { "c128", C128MODEL_C128_PAL },
    { "c128dcr", C128MODEL_C128DCR_PAL },
    { "pal", C128MODEL_C128_PAL },
    { "ntsc", C128MODEL_C128_NTSC },
    { NULL, C128MODEL_UNKNOWN }
};

static int set_c128_model(const char *param, void *extra_param)
{
    int model = C128MODEL_UNKNOWN;
    int i = 0;

    if (!param) {
        return -1;
    }

    do {
        if (strcmp(model_match[i].name, param) == 0) {
            model = model_match[i].model;
        }
        i++;
    } while ((model == C128MODEL_UNKNOWN) && (model_match[i].name != NULL));

    if (model == C128MODEL_UNKNOWN) {
        return -1;
    }

    c128model_set(model);

    return 0;
}

static const cmdline_option_t cmdline_options[] = {
    { "-pal", SET_RESOURCE, 0,
      NULL, NULL, "MachineVideoStandard", (void *)MACHINE_SYNC_PAL,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDGS_UNUSED, IDGS_UNUSED,
      NULL, "Use PAL sync factor" },
    { "-ntsc", SET_RESOURCE, 0,
      NULL, NULL, "MachineVideoStandard", (void *)MACHINE_SYNC_NTSC,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDGS_UNUSED, IDGS_UNUSED,
      NULL, "Use NTSC sync factor" },
    { "-kernal", SET_RESOURCE, 1,
      NULL, NULL, "KernalIntName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDGS_UNUSED, IDGS_UNUSED,
      "<Name>", "Specify name of international Kernal ROM image" },
    { "-kernalde", SET_RESOURCE, 1,
      NULL, NULL, "KernalDEName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDGS_UNUSED, IDGS_UNUSED,
      "<Name>", "Specify name of German Kernal ROM image" },
    { "-kernalfi", SET_RESOURCE, 1,
      NULL, NULL, "KernalFIName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDGS_UNUSED, IDGS_UNUSED,
      "<Name>", "Specify name of Finnish Kernal ROM image" },
    { "-kernalfr", SET_RESOURCE, 1,
      NULL, NULL, "KernalFRName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_FR_KERNEL_NAME,
      "<Name>", NULL },
    { "-kernalit", SET_RESOURCE, 1,
      NULL, NULL, "KernalITName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_IT_KERNEL_NAME,
      "<Name>", NULL },
    { "-kernalno", SET_RESOURCE, 1,
      NULL, NULL, "KernalNOName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_NO_KERNEL_NAME,
      "<Name>", NULL },
    { "-kernalse", SET_RESOURCE, 1,
      NULL, NULL, "KernalSEName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_SV_KERNEL_NAME,
      "<Name>", NULL },
    { "-kernalch", SET_RESOURCE, 1,
      NULL, NULL, "KernalCHName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_CH_KERNEL_NAME,
      "<Name>", NULL },
    { "-basiclo", SET_RESOURCE, 1,
      NULL, NULL, "BasicLoName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_BASIC_ROM_NAME_LOW,
      "<Name>", NULL },
    { "-basichi", SET_RESOURCE, 1,
      NULL, NULL, "BasicHiName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_BASIC_ROM_NAME_HIGH,
      "<Name>", NULL },
    { "-chargen", SET_RESOURCE, 1,
      NULL, NULL, "ChargenIntName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_INT_CHARGEN_ROM_NAME,
      "<Name>", NULL },
    { "-chargde", SET_RESOURCE, 1,
      NULL, NULL, "ChargenDEName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_DE_CHARGEN_ROM_NAME,
      "<Name>", NULL },
    { "-chargfr", SET_RESOURCE, 1,
      NULL, NULL, "ChargenFRName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_FR_CHARGEN_ROM_NAME,
      "<Name>", NULL },
    { "-chargse", SET_RESOURCE, 1,
      NULL, NULL, "ChargenSEName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_SV_CHARGEN_ROM_NAME,
      "<Name>", NULL },
    { "-chargch", SET_RESOURCE, 1,
      NULL, NULL, "ChargenCHName", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_CH_CHARGEN_ROM_NAME,
      "<Name>", NULL },
    { "-kernal64", SET_RESOURCE, 1,
      NULL, NULL, "Kernal64Name", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_C64_MODE_KERNAL_NAME,
      "<Name>", NULL },
    { "-basic64", SET_RESOURCE, 1,
      NULL, NULL, "Basic64Name", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SPECIFY_C64_MODE_BASIC_NAME,
      "<Name>", NULL },
#if defined(HAVE_RS232DEV) || defined(HAVE_RS232NET)
    { "-acia1", SET_RESOURCE, 0,
      NULL, NULL, "Acia1Enable", (void *)1,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDCLS_UNUSED, IDGS_UNUSED,
      NULL, "Enable the ACIA RS232 interface emulation" },
    { "+acia1", SET_RESOURCE, 0,
      NULL, NULL, "Acia1Enable", (void *)0,
      USE_PARAM_STRING, USE_DESCRIPTION_STRING,
      IDCLS_UNUSED, IDGS_UNUSED,
      NULL, "Disable the ACIA RS232 interface emulation" },
#endif
    { "-ciamodel", CALL_FUNCTION, 1,
      set_cia_model, NULL, NULL, NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SET_BOTH_CIA_MODELS,
      "<Model>", NULL },
    { "-cia1model", SET_RESOURCE, 1,
      NULL, NULL, "CIA1Model", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SET_CIA1_MODEL,
      "<Model>", NULL },
    { "-cia2model", SET_RESOURCE, 1,
      NULL, NULL, "CIA2Model", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SET_CIA2_MODEL,
      "<Model>", NULL },
    { "-model", CALL_FUNCTION, 1,
      set_c128_model, NULL, NULL, NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SET_C128_MODEL,
      "<Model>", NULL },
    { "-machinetype", SET_RESOURCE, 1,
      NULL, NULL, "MachineType", NULL,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDGS_UNUSED, IDCLS_SET_C128_MACHINE_TYPE,
      "<Type>", NULL },
    { "-c128fullbanks", SET_RESOURCE, 0,
      NULL, NULL, "C128FullBanks", (void *)1,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDCLS_UNUSED, IDCLS_ENABLE_C128_FULL_BANKS,
      NULL, NULL },
    { "+c128fullbanks", SET_RESOURCE, 0,
      NULL, NULL, "C128FullBanks", (void *)0,
      USE_PARAM_STRING, USE_DESCRIPTION_ID,
      IDCLS_UNUSED, IDCLS_DISABLE_C128_FULL_BANKS,
      NULL, NULL },
    CMDLINE_LIST_END
};

int c128_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}
