/*
 * retroreplay.c - Cartridge handling, Retro Replay cart.
 *
 * Written by
 *  Andreas Boose <viceteam@t-online.de>
 *  groepaz <groepaz@gmx.net>
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
#include <string.h>

#include "c64cart.h"
#include "c64cartmem.h"
#include "c64export.h"
#include "c64io.h"
#include "cmdline.h"
#include "flash040.h"
#include "lib.h"
#include "maincpu.h"
#include "retroreplay.h"
#include "reu.h"
#include "resources.h"
#ifdef HAVE_TFE
#include "tfe.h"
#endif
#include "translate.h"
#include "types.h"
#include "util.h"

/*
    Retro Replay (Individual Computers)

    64K rom, 8*8k pages (actually 128K Flash ROM, one of two 64K banks selected by bank jumper)
    32K ram, 4*8k pages

    io1
        - registers at de00/de01
        - cart RAM (if enabled) or cart ROM

    io2
        - cart RAM (if enabled) or cart ROM
*/

/* #define DEBUGRR */

#ifdef DEBUGRR
#define DBG(x)  printf x
#else
#define DBG(x)
#endif

/* Cart is activated.  */
unsigned int rr_active;
unsigned int rr_clockport_enabled;

/* current bank */
static unsigned int rr_bank;

/* Only one write access is allowed.  */
static unsigned int write_once;

/* RAM bank switching allowed.  */
static unsigned int allow_bank;

/* Freeze is disallowed.  */
static int no_freeze;

/* REU compatibility mapping.  */
unsigned int reu_mapping;

static int rr_hw_flashjumper;
static int rr_hw_bankjumper;
static int rr_bios_write;

static unsigned int rom_offset;

/* the 29F010 statemachine */
static flash040_context_t *flashrom_state = NULL;

/* ---------------------------------------------------------------------*/

/* some prototypes are needed */
static BYTE REGPARM1 retroreplay_io1_read(WORD addr);
static void REGPARM2 retroreplay_io1_store(WORD addr, BYTE value);
static BYTE REGPARM1 retroreplay_io2_read(WORD addr);
static void REGPARM2 retroreplay_io2_store(WORD addr, BYTE value);

static io_source_t retroreplay_io1_device = {
    "Retro Replay",
    IO_DETACH_CART,
    NULL,
    0xde00, 0xdeff, 0xff,
    0,
    retroreplay_io1_store,
    retroreplay_io1_read
};

static io_source_t retroreplay_io2_device = {
    "Retro Replay",
    IO_DETACH_CART,
    NULL,
    0xdf00, 0xdfff, 0xff,
    0,
    retroreplay_io2_store,
    retroreplay_io2_read
};

static io_source_list_t *retroreplay_io1_list_item = NULL;
static io_source_list_t *retroreplay_io2_list_item = NULL;

/* ---------------------------------------------------------------------*/

BYTE REGPARM1 retroreplay_io1_read(WORD addr)
{
    retroreplay_io1_device.io_source_valid = 0;
    
/* DBG(("io1 r %04x\n",addr)); */

    if (rr_active) {
        switch (addr & 0xff) {
            /*
                $de00 read or $de01 read:
                    Bit 0: 1=Flashmode active (jumper set)
                    Bit 1: feedback of AllowBank bit
                    Bit 2: 1=Freeze button pressed
                    Bit 3: feedback of banking bit 13
                    Bit 4: feedback of banking bit 14
                    Bit 5: feedback of banking bit 16
                    Bit 6: 1=REU compatible memory map active
                    Bit 7: feedback of banking bit 15
             */
            case 0:
            case 1:
                retroreplay_io1_device.io_source_valid = 1;
                return ((roml_bank & 3) << 3) | ((roml_bank & 4) << 5) | ((roml_bank & 8) << 2) | allow_bank | reu_mapping | rr_hw_flashjumper;
            default:
#ifdef HAVE_TFE
                if (rr_clockport_enabled && tfe_enabled && tfe_as_rr_net && (addr & 0xff) < 0x10) {
                    return 0;
                }
#endif
                if (reu_mapping) {
                    retroreplay_io1_device.io_source_valid = 1;
                    if (export_ram) {
                        if (allow_bank) {
                            switch (roml_bank & 3) {
                                case 0:
                                    return export_ram0[0x1e00 + (addr & 0xff)];
                                case 1:
                                    return export_ram0[0x3e00 + (addr & 0xff)];
                                case 2:
                                    return export_ram0[0x5e00 + (addr & 0xff)];
                                case 3:
                                    return export_ram0[0x7e00 + (addr & 0xff)];
                            }
                        } else {
                            return export_ram0[0x1e00 + (addr & 0xff)];
                        }
                    }

                    return flash040core_read(flashrom_state, rom_offset + ((addr | 0xde00) & 0x1fff) + (roml_bank << 13));
                }
        }
    }
    return 0;
}

void REGPARM2 retroreplay_io1_store(WORD addr, BYTE value)
{
    int mode = CMODE_WRITE;

    DBG(("io1 w %04x %02x\n",addr,value));

    if (rr_active) {
        switch (addr & 0xff) {
            /*
                $de00 write:

                This register is reset to $00 on a hard reset if not in flash mode.

                If in flash mode, it is set to $02 in order to prevent the computer
                from starting the normal cartridge. Flash mode is selected with a jumper.

                Bit 0 controls the GAME line: A 1 asserts the line, a 0 will deassert it.
                Bit 1 controls the EXROM line: A 0 will assert it, a 1 will deassert it.
                Bit 2 Writing a 1 to bit 2 will disable further write accesses to all
                    registers of Retro Replay, and set the memory map of the C-64
                    to standard, as if there is no cartridge installed at all.
                Bit 3 controls bank-address 13 for ROM and RAM banking
                Bit 4 controls bank-address 14 for ROM and RAM banking
                Bit 5 switches between ROM and RAM: 0=ROM, 1=RAM
                Bit 6 must be written once to "1" after a successful freeze in
                    order to set the correct memory map and enable Bits 0 and 1
                    of this register. Otherwise no effect.
                Bit 7 controls bank-address 15 for ROM banking
             */
            case 0:
                rr_bank = ((value >> 3) & 3) | ((value >> 5) & 4);
                if (value & 0x40) {
                    mode |= CMODE_RELEASE_FREEZE;
                }
                if (value & 0x20) {
                    mode |= CMODE_EXPORT_RAM;
                }

                if (rr_hw_flashjumper) {
                    /* FIXME: what exactly is really happening ? */
                    if((value & 3) == 3) {
                        value = 0;
                    } else if((value & 3) == 1) {
                        value = 0;
                    }
                }
                cartridge_config_changed(0, (value & 3) | (rr_bank << CMODE_BANK_SHIFT), mode);

                if (value & 4) {
                    rr_active = 0;
                }
                break;
            /*
                $de01 write: Extended control register.

                    If not in Flash mode, bits 1, 2 and 6 can only be written once.
                    Bit 5 is always set to 0 if not in flash mode.

                    If in Flash mode, the REUcomp bit cannot be set, but the register
                    will not be disabled by the first write.

                    Bit 0: enable accessory connector. See further down.
                    Bit 1: AllowBank  (1 allows banking of RAM in $df00/$de02 area)
                    Bit 2: NoFreeze   (1 disables Freeze function)
                    Bit 3: bank-address 13 for RAM and ROM (mirror of $de00)
                    Bit 4: bank-address 14 for RAM and ROM (mirror of $de00)
                    Bit 5: bank-address 16 for ROM (only in flash mode)
                    Bit 6: REU compatibility bit. 0=standard memory map
                                                1=REU compatible memory map
                    Bit 7: bank-address 15 for ROM (mirror of $de00)
             */
            case 1:
                if (rr_hw_flashjumper) {
                    rr_bank = ((value >> 3) & 3) | ((value >> 5) & 4) | ((value >> 2) & 8);
                    cartridge_romhbank_set(rr_bank);
                    cartridge_romlbank_set(rr_bank);
                    allow_bank = value & 2;
                    no_freeze = value & 4;
                    reu_mapping = 0; /* can not be set in flash mode */
                } else {
                    if (write_once == 0) {
                        rr_bank = ((value >> 3) & 3) | ((value >> 5) & 4);
                        cartridge_romhbank_set(rr_bank);
                        cartridge_romlbank_set(rr_bank);
                        allow_bank = value & 2;
                        no_freeze = value & 4;
                        reu_mapping = value & 0x40;
                        if (rr_clockport_enabled != (unsigned int)(value & 1)) {
                            rr_clockport_enabled = value & 1;
#ifdef HAVE_TFE
                            tfe_clockport_changed();
#endif
                        }
                        write_once = 1;
                    }
                }
                break;
            default:
#ifdef HAVE_TFE
                if (rr_clockport_enabled && tfe_enabled && tfe_as_rr_net && (addr & 0xff) < 0x10) {
                    return;
                }
#endif
                if (reu_mapping) {
                    if (export_ram) {
                        if (allow_bank) {
                            switch (roml_bank & 3) {
                                case 0:
                                    export_ram0[0x1e00 + (addr & 0xff)] = value;
                                    break;
                                case 1:
                                    export_ram0[0x3e00 + (addr & 0xff)] = value;
                                    break;
                                case 2:
                                    export_ram0[0x5e00 + (addr & 0xff)] = value;
                                    break;
                                case 3:
                                    export_ram0[0x7e00 + (addr & 0xff)] = value;
                                    break;
                            }
                        } else {
                            export_ram0[0x1e00 + (addr & 0xff)] = value;
                        }
                    }
                }
        }
    }
}

BYTE REGPARM1 retroreplay_io2_read(WORD addr)
{
    retroreplay_io2_device.io_source_valid = 0;

    DBG(("io2 r %04x\n",addr));

    if (rr_active) {
        if (!reu_mapping) {
            retroreplay_io2_device.io_source_valid = 1;
            if (export_ram) {
                if (allow_bank) {
                    switch (roml_bank & 3) {
                        case 0:
                            return export_ram0[0x1f00 + (addr & 0xff)];
                        case 1:
                            return export_ram0[0x3f00 + (addr & 0xff)];
                        case 2:
                            return export_ram0[0x5f00 + (addr & 0xff)];
                        case 3:
                            return export_ram0[0x7f00 + (addr & 0xff)];
                    }
                } else {
                    return export_ram0[0x1f00 + (addr & 0xff)];
                }
            }

            return flash040core_read(flashrom_state, rom_offset + ((addr | 0xdf00) & 0x1fff) + (roml_bank << 13));
        }
    }
    return 0;
}

void REGPARM2 retroreplay_io2_store(WORD addr, BYTE value)
{
    DBG(("io2 w %04x %02x\n",addr,value));

    if (rr_active) {
        if (!reu_mapping) {
            if (export_ram) {
                if (allow_bank) {
                    switch (roml_bank & 3) {
                        case 0:
                            export_ram0[0x1f00 + (addr & 0xff)] = value;
                            break;
                        case 1:
                            export_ram0[0x3f00 + (addr & 0xff)] = value;
                            break;
                        case 2:
                            export_ram0[0x5f00 + (addr & 0xff)] = value;
                            break;
                        case 3:
                            export_ram0[0x7f00 + (addr & 0xff)] = value;
                            break;
                    }
                } else {
                    export_ram0[0x1f00 + (addr & 0xff)] = value;
                }
            }
        }
    }
}

/* ---------------------------------------------------------------------*/

BYTE REGPARM1 retroreplay_roml_read(WORD addr)
{
    if (export_ram) {
        switch (roml_bank & 3) {
            case 0:
                return export_ram0[addr & 0x1fff];
            case 1:
                return export_ram0[(addr & 0x1fff) + 0x2000];
            case 2:
                return export_ram0[(addr & 0x1fff) + 0x4000];
            case 3:
                return export_ram0[(addr & 0x1fff) + 0x6000];
        }
    }

    return flash040core_read(flashrom_state, rom_offset + (addr & 0x1fff) + (roml_bank << 13));
}

void REGPARM2 retroreplay_roml_store(WORD addr, BYTE value)
{
/*    DBG(("roml w %04x %02x ram:%d flash:%d\n", addr, value, export_ram, rr_hw_flashjumper)); */

    if (export_ram) {
        switch (roml_bank & 3) {
            case 0:
                export_ram0[addr & 0x1fff] = value;
                break;
            case 1:
                export_ram0[(addr & 0x1fff) + 0x2000] = value;
                break;
            case 2:
                export_ram0[(addr & 0x1fff) + 0x4000] = value;
                break;
            case 3:
                export_ram0[(addr & 0x1fff) + 0x6000] = value;
                break;
        }
    } else {
        /* FIXME: is this correct? perhaps its _always_ ROM in flash mode ? */
        if (rr_hw_flashjumper) {
            flash040core_store(flashrom_state, rom_offset + (addr & 0x1fff) + (roml_bank << 13), value);
        }
    }
}

BYTE REGPARM1 retroreplay_romh_read(WORD addr)
{
    return flash040core_read(flashrom_state, rom_offset + (addr & 0x1fff) + (roml_bank << 13));
}

/* ---------------------------------------------------------------------*/

void retroreplay_freeze(void)
{
    /* freeze button is disabled in flash mode */
    if (!rr_hw_flashjumper) {
        rr_active = 1;
        cartridge_config_changed(3, 3, CMODE_READ | CMODE_EXPORT_RAM);
        flash040core_reset(flashrom_state);
    }
}

int retroreplay_freeze_allowed(void)
{
    if (no_freeze) {
        return 0;
    }
    return 1;
}

void retroreplay_config_init(void)
{
    DBG(("retroreplay_config_init flash:%d bank jumper: %d offset: %08x\n",rr_hw_flashjumper , rr_hw_bankjumper, rom_offset));

    rr_active = 1;
    rr_clockport_enabled = 0;
    write_once = 0;
    no_freeze = 0;
    reu_mapping = 0;
    allow_bank = 0;

    if (rr_hw_flashjumper) {
        cartridge_config_changed(2, 2, CMODE_READ);
    } else {
        cartridge_config_changed(0, 0, CMODE_READ);
    }

    flash040core_reset(flashrom_state);
}

void retroreplay_reset(void)
{
    DBG(("retroreplay_reset flash:%d bank jumper: %d offset: %08x\n",rr_hw_flashjumper , rr_hw_bankjumper, rom_offset));
    rr_active = 1;

    if (rr_hw_flashjumper) {
        cartridge_config_changed(2, 2, CMODE_READ);
    } else {
        cartridge_config_changed(0, 0, CMODE_READ);
    }

    flash040core_reset(flashrom_state);
}

void retroreplay_config_setup(BYTE *rawcart)
{
    DBG(("retroreplay_config_setup bank jumper: %d offset: %08x\n", rr_hw_bankjumper, rom_offset));

    if (rr_hw_flashjumper) {
        cartridge_config_changed(2, 2, CMODE_READ);
    } else {
        cartridge_config_changed(0, 0, CMODE_READ);
    }

    flashrom_state = lib_malloc(sizeof(flash040_context_t));
    flash040core_init(flashrom_state, maincpu_alarm_context, FLASH040_TYPE_010, roml_banks);
    memcpy(flashrom_state->flash_data, rawcart, 0x20000);    
}

/* ---------------------------------------------------------------------*/

static const c64export_resource_t export_res = {
    "Retro Replay", 1, 1
};

static int set_rr_flashjumper(int val, void *param)
{
    rr_hw_flashjumper = val;
    return 0;
}

static int set_rr_bankjumper(int val, void *param)
{
    /* FIXME: needs confirmation: it appears that when the jumper is set, bank 0 is selected */
    rr_hw_bankjumper = val;
    if(rr_hw_bankjumper) {
        rom_offset = 0x0;
    } else {
        rom_offset = 0x10000;
    }
    DBG(("bank jumper: %d offset: %08x\n", rr_hw_bankjumper, rom_offset));
    return 0;
}

static int set_rr_bios_write(int val, void *param)
{
    rr_bios_write = val;
    return 0;
}

static const resource_int_t resources_int[] = {
  { "RR_flashjumper", 0, RES_EVENT_NO, NULL,
    &rr_hw_flashjumper, set_rr_flashjumper, NULL },
  { "RR_bankjumper", 0, RES_EVENT_NO, NULL,
    &rr_hw_bankjumper, set_rr_bankjumper, NULL },
  { "RR_bios_write", 0, RES_EVENT_NO, NULL,
    &rr_bios_write, set_rr_bios_write, NULL },
  { NULL }
};

int retroreplay_resources_init(void)
{
    return resources_register_int(resources_int);
}

void retroreplay_resources_shutdown(void)
{

}

/* ------------------------------------------------------------------------- */

static const cmdline_option_t cmdline_options[] =
{
  /* FIXME: ARGS. someone document how to use these defines */
  { "-rrbioswrite", SET_RESOURCE, 0,
    NULL, NULL, "RR_bios_write", (resource_value_t)1,
    USE_PARAM_STRING, USE_DESCRIPTION_ID,
    IDCLS_UNUSED, IDCLS_MMC64_BIOS_WRITE, /* FIXME */
    NULL, NULL },
  { NULL }
};

int retroreplay_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}

static int retroreplay_common_attach(void)
{
    if (c64export_add(&export_res) < 0) {
        return -1;
    }

    retroreplay_io1_list_item = c64io_register(&retroreplay_io1_device);
    retroreplay_io2_list_item = c64io_register(&retroreplay_io2_device);

    return 0;
}

int retroreplay_bin_attach(const char *filename, BYTE *rawcart)
{
    int len = 0;
    FILE *fd;

    /* we accept 32k, 64k and full 128k images */

    fd = fopen(filename, "rb");
    len = util_file_length(fd);
    fclose(fd);

    switch (len) {
        case 0x8000: /* 32K */
            if (util_file_load(filename, &rawcart[0x10000], 0x8000, UTIL_FILE_LOAD_SKIP_ADDRESS) < 0) {
                return -1;
            }
            break;
        case 0x10000: /* 64K */
            if (util_file_load(filename, &rawcart[0x10000], 0x10000, UTIL_FILE_LOAD_SKIP_ADDRESS) < 0) {
                return -1;
            }
            break;
        case 0x20000: /* 128K */
            if (util_file_load(filename, rawcart, 0x20000, UTIL_FILE_LOAD_SKIP_ADDRESS) < 0) {
                return -1;
            }
            break;
        default:
            return -1;
    }

    return retroreplay_common_attach();
}

/* a valid RR CRT is always 64K */
int retroreplay_crt_attach(FILE *fd, BYTE *rawcart)
{
    BYTE chipheader[0x10];
    int i;

    for (i = 0; i <= 7; i++) {
        if (fread(chipheader, 0x10, 1, fd) < 1) {
            return -1;
        }

        if (chipheader[0xb] > 7) {
            return -1;
        }

        if (fread(&rawcart[chipheader[0xb] << 13], 0x2000, 1, fd) < 1) {
            return -1;
        }
    }

    return retroreplay_common_attach();
}

void retroreplay_detach(void)
{
    /* FIXME: save rr rom image (if enabled) */

    flash040core_shutdown(flashrom_state);
    lib_free(flashrom_state);
    c64export_remove(&export_res);
    c64io_unregister(retroreplay_io1_list_item);
    c64io_unregister(retroreplay_io2_list_item);
    retroreplay_io1_list_item = NULL;
    retroreplay_io2_list_item = NULL;
}
