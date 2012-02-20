/*
 * monitor.c - The VICE built-in monitor.
 *
 * Written by
 *  Daniel Sladic <sladic@eecg.toronto.edu>
 *  Ettore Perazzoli <ettore@comm2000.it>
 *  Andreas Boose <viceteam@t-online.de>
 *  Daniel Kahlin <daniel@kahlin.net>
 *  Thomas Giesel <skoe@directbox.com>
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

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __IBMC__
#include <direct.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "archdep.h"
#include "charset.h"
#include "cmdline.h"
#include "console.h"
#include "datasette.h"
#include "drive.h"
#include "drivecpu.h"

#ifdef HAVE_FULLSCREEN
#include "fullscreenarch.h"
#endif

#include "interrupt.h"
#include "ioutil.h"
#include "kbdbuf.h"
#include "lib.h"
#include "log.h"
#include "machine.h"
#include "machine-video.h"
#include "mem.h"
#include "mon_breakpoint.h"
#include "mon_disassemble.h"
#include "mon_memory.h"
#include "asm.h"
#include "mon_parse.h"
#include "mon_parsers.h"
#include "mon_register.h"
#include "mon_ui.h"
#include "mon_util.h"
#include "monitor.h"
#include "monitor_network.h"
#include "montypes.h"
#include "resources.h"
#include "screenshot.h"
#include "signals.h"
#include "sysfile.h"
#include "translate.h"
#include "traps.h"
#include "types.h"
#include "uiapi.h"
#include "uimon.h"
#include "util.h"
#include "vsync.h"


int mon_stop_output;

int mon_init_break = -1;

/* Defines */

#define MAX_LABEL_LEN 255
#define MAX_MEMSPACE_NAME_LEN 10
#define HASH_ARRAY_SIZE 256
#define HASH_ADDR(x) ((x)%0xff)
#define OP_JSR 0x20
#define OP_RTI 0x40
#define OP_RTS 0x60

#define ADDR_LIMIT(x) (addr_mask(x))
#define BAD_ADDR (new_addr(e_invalid_space, 0))

#define MONITOR_GET_PC(mem) \
    ((WORD)((monitor_cpu_for_memspace[mem]->mon_register_get_val)(mem, e_PC)))

#define MONITOR_GET_OPCODE(mem) (mon_get_mem_val(mem, MONITOR_GET_PC(mem)))

console_t *console_log = NULL;

static int monitor_trap_triggered = 0;

monitor_cartridge_commands_t mon_cart_cmd;

/* Types */

struct symbol_entry {
   WORD addr;
   char *name;
   struct symbol_entry *next;
};
typedef struct symbol_entry symbol_entry_t;

struct symbol_table {
   symbol_entry_t *name_list;
   symbol_entry_t *addr_hash_table[HASH_ARRAY_SIZE];
};
typedef struct symbol_table symbol_table_t;

/* Global variables */

static char *last_cmd = NULL;
int exit_mon = 0;
int mon_console_close_on_leaving = 1;


int sidefx;
RADIXTYPE default_radix;
MEMSPACE default_memspace;

static bool inside_monitor = FALSE;
static unsigned int instruction_count;
static bool skip_jsrs;
static int wait_for_return_level;
static bool trigger_break_on_next_instruction;

static int parse_pos;
static int prev_parse_pos;

const char *_mon_space_strings[] = {
    "Default", "Computer", "Disk8", "Disk9", "Disk10", "Disk11", "<<Invalid>>"
};

static WORD watch_load_array[10][NUM_MEMSPACES];
static WORD watch_store_array[10][NUM_MEMSPACES];
static unsigned int watch_load_count[NUM_MEMSPACES];
static unsigned int watch_store_count[NUM_MEMSPACES];
static symbol_table_t monitor_labels[NUM_MEMSPACES];
static CLOCK stopwatch_start_time[NUM_MEMSPACES];
bool force_array[NUM_MEMSPACES];
monitor_interface_t *mon_interfaces[NUM_MEMSPACES];

MON_ADDR dot_addr[NUM_MEMSPACES];
unsigned char data_buf[256];
unsigned char data_mask_buf[256];
unsigned int data_buf_len;
bool asm_mode;
MON_ADDR asm_mode_addr;
static unsigned int next_or_step_stop;
unsigned monitor_mask[NUM_MEMSPACES];

static bool watch_load_occurred;
static bool watch_store_occurred;

static bool recording;
static FILE *recording_fp;
static char *recording_name;
#define MAX_PLAYBACK 8
int playback = 0;
char *playback_name = NULL;
static void playback_commands(int current_playback);
static int set_playback_name(const char *param, void *extra_param);

/* Disassemble the current opcode on entry.  Used for single step.  */
static int disassemble_on_entry = 0;

/* We now have an array of pointers to the current monitor_cpu_type for each memspace. */
/* This gets initialized in monitor_init(). */
monitor_cpu_type_t *monitor_cpu_for_memspace[NUM_MEMSPACES];

struct supported_cpu_type_list_s {
    monitor_cpu_type_t *monitor_cpu_type_p;
    struct supported_cpu_type_list_s *next;
};
typedef struct supported_cpu_type_list_s supported_cpu_type_list_t;

/* A linked list of supported monitor_cpu_types for each memspace */
static supported_cpu_type_list_t *monitor_cpu_type_supported[NUM_MEMSPACES];

struct monitor_cpu_type_list_s {
    monitor_cpu_type_t monitor_cpu_type;
    struct monitor_cpu_type_list_s *next_monitor_cpu_type;
};
typedef struct monitor_cpu_type_list_s monitor_cpu_type_list_t;

static monitor_cpu_type_list_t *monitor_cpu_type_list = NULL;

static const char *cond_op_string[] = { "",
                                        "==",
                                        "!=",
                                        ">",
                                        "<",
                                        ">=",
                                        "<=",
                                        "&&",
                                        "||"
                                       };

const char *mon_memspace_string[] = {"default", "C", "8", "9", "0", "1" };

static const char *register_string[] = { "A",
                                         "X",
                                         "Y",
                                         "PC",
                                         "SP"
                                        };

/* Some local helper functions */
int find_cpu_type_from_string(const char *cpu_string)
{
    if ((strcasecmp(cpu_string, "6502")==0)||(strcasecmp(cpu_string, "6510")==0)) {
        return CPU_6502;
    } else if (strcasecmp(cpu_string, "h6809")==0||strcmp(cpu_string, "6809")==0) {
        return CPU_6809;
    } else if (strcasecmp(cpu_string, "z80")==0) {
        return CPU_Z80;
    } else if ((strcasecmp(cpu_string, "6502dtv")==0)||(strcasecmp(cpu_string, "6510dtv")==0)) {
        return CPU_6502DTV;
    } else {
        return -1;
    }
}

monitor_cpu_type_t* monitor_find_cpu_for_memspace(MEMSPACE mem, CPU_TYPE_t cpu)
{
    supported_cpu_type_list_t *ptr;
    if (mem==e_default_space)
        mem=default_memspace;
    ptr=monitor_cpu_type_supported[mem];
    while (ptr) {
        if (ptr->monitor_cpu_type_p) {
            if (ptr->monitor_cpu_type_p->cpu_type==cpu) {
                return ptr->monitor_cpu_type_p;
            }
        }
        ptr=ptr->next;
    }
    return NULL;
}

void monitor_print_cpu_types_supported(MEMSPACE mem)
{
    supported_cpu_type_list_t *ptr;
    ptr=monitor_cpu_type_supported[mem];
    while (ptr) {
        if (ptr->monitor_cpu_type_p) {
            switch (ptr->monitor_cpu_type_p->cpu_type) {
            case CPU_6502:
                mon_out(" 6502");
                break;
            case CPU_6502DTV:
                mon_out(" 6502DTV");
                break;
            case CPU_6809:
                mon_out(" 6809");
                break;
            case CPU_Z80:
                mon_out(" Z80");
                break;
            default:
                mon_out(" unknown(%d)",ptr->monitor_cpu_type_p->cpu_type);
                break;
            }
        }
        ptr=ptr->next;
    }
    mon_out("\n");
}

/* *** ADDRESS FUNCTIONS *** */


static void set_addr_memspace(MON_ADDR *a, MEMSPACE m)
{
    *a = new_addr(m, addr_location(*a));
}

bool mon_is_valid_addr(MON_ADDR a)
{
    return addr_memspace(a) != e_invalid_space;
}

bool mon_inc_addr_location(MON_ADDR *a, unsigned inc)
{
    unsigned new_loc = addr_location(*a) + inc;
    *a = new_addr(addr_memspace(*a), addr_mask(new_loc));

    return !(new_loc == addr_location(new_loc));
}

void mon_evaluate_default_addr(MON_ADDR *a)
{
    if (addr_memspace(*a) == e_default_space)
        set_addr_memspace(a, default_memspace);
}

bool mon_is_in_range(MON_ADDR start_addr, MON_ADDR end_addr, unsigned loc)
{
    unsigned start, end;

    start = addr_location(start_addr);

    if (!mon_is_valid_addr(end_addr))
        return (loc == start);

    end = addr_location(end_addr);

    if (end < start)
        return ((loc >= start) || (loc <= end));

    return ((loc >= start) && (loc<=end));
}

static bool is_valid_addr_range(MON_ADDR start_addr, MON_ADDR end_addr)
{
    if (addr_memspace(start_addr) == e_invalid_space)
        return FALSE;

    if ((addr_memspace(start_addr) != addr_memspace(end_addr)) &&
         ((addr_memspace(start_addr) != e_default_space) ||
         (addr_memspace(end_addr) != e_default_space))) {
        return FALSE;
    }
    return TRUE;
}

static unsigned get_range_len(MON_ADDR addr1, MON_ADDR addr2)
{
    WORD start, end;
    unsigned len = 0;

    start = addr_location(addr1);
    end  = addr_location(addr2);

    if (start <= end) {
       len = end - start + 1;
    } else {
       len = (0xffff - start) + end + 1;
    }

    return len;
}

long mon_evaluate_address_range(MON_ADDR *start_addr, MON_ADDR *end_addr,
                                bool must_be_range, WORD default_len)
{
    long len = default_len;

    /* Check if we DEFINITELY need a range. */
    if (!is_valid_addr_range(*start_addr, *end_addr) && must_be_range)
        return -1;

    if (is_valid_addr_range(*start_addr, *end_addr)) {
        MEMSPACE mem1, mem2;
        /* Resolve any default memory spaces. We wait until now because we
         * need both addresses - if only 1 is a default, use the other to
         * resolve the memory space.
         */
        mem1 = addr_memspace(*start_addr);
        mem2 = addr_memspace(*end_addr);

        if (mem1 == e_default_space) {
            if (mem2 == e_default_space) {
                set_addr_memspace(start_addr, default_memspace);
                set_addr_memspace(end_addr, default_memspace);
            } else {
                if (mem2 != e_invalid_space) {
                    set_addr_memspace(start_addr, mem2);
                } else {
                    set_addr_memspace(start_addr, default_memspace);
                }
            }
        } else {
            if (mem2 == e_default_space) {
                set_addr_memspace(end_addr, mem1);
            } else {
                if (mem2 != e_invalid_space) {
                    if (!(mem1 == mem2)) {
                        log_error(LOG_ERR, "Invalid memspace!");
                        return 0;
                    }
                } else {
                    log_error(LOG_ERR, "Invalid memspace!");
                    return 0;
                }
            }
        }

        len = get_range_len(*start_addr, *end_addr);
    } else {
        if (!mon_is_valid_addr(*start_addr))
            *start_addr = dot_addr[(int)default_memspace];
        else
            mon_evaluate_default_addr(start_addr);

        if (!mon_is_valid_addr(*end_addr)) {
            *end_addr = *start_addr;
            mon_inc_addr_location(end_addr, len);
        } else {
            set_addr_memspace(end_addr,addr_memspace(*start_addr));
            len = get_range_len(*start_addr, *end_addr);
        }
    }

    return len;
}


/* *** REGISTER AND MEMORY OPERATIONS *** */

mon_reg_list_t *mon_register_list_get(int mem)
{
    return monitor_cpu_for_memspace[mem]->mon_register_list_get(mem);
}

bool check_drive_emu_level_ok(int drive_num)
{
    if (drive_num < 8 || drive_num > 11)
        return FALSE;

    if (mon_interfaces[monitor_diskspace_mem(drive_num - 8)] == NULL) {
        mon_out("True drive emulation not supported for this machine.\n");
        return FALSE;
    }

    return TRUE;
}

void monitor_cpu_type_set(const char *cpu_type)
{
    int serchcpu;
    monitor_cpu_type_t *monitor_cpu_type_p=NULL;

    serchcpu=find_cpu_type_from_string(cpu_type);
    if (serchcpu>-1) {
        monitor_cpu_type_p=monitor_find_cpu_for_memspace(default_memspace, serchcpu);
    }
    if (monitor_cpu_type_p) {
        monitor_cpu_for_memspace[default_memspace]=monitor_cpu_type_p;
        uimon_notify_change();
    } else {
        if (strcmp(cpu_type,"")!=0) {
            mon_out("Unknown CPU type `%s'\n", cpu_type);
        }
        mon_out("This device (%s) supports the following CPU types:", _mon_space_strings[default_memspace]);
        monitor_print_cpu_types_supported(default_memspace);
    }
}

void mon_bank(MEMSPACE mem, const char *bankname)
{
    if (mem == e_default_space)
        mem = default_memspace;

    if (!mon_interfaces[mem]->mem_bank_list) {
        mon_out("Banks not available in this memspace\n");
        return;
    }

    if (bankname == NULL) {
        const char **bnp;

        bnp = mon_interfaces[mem]->mem_bank_list();
        mon_out("Available banks (some may be equivalent to others):\n");
        while (*bnp) {
            if (mon_interfaces[mem]->mem_bank_from_name(*bnp) == mon_interfaces[mem]->current_bank) {
                mon_out("*");
            }
            mon_out("%s \t", *bnp);
            bnp++;
        }
        mon_out("\n");
    } else {
        int newbank;

        newbank = mon_interfaces[mem]->mem_bank_from_name(bankname);
        if (newbank < 0) {
            mon_out("Unknown bank name `%s'\n", bankname);
            return;
        }
        mon_interfaces[mem]->current_bank = newbank;
    }
}

const char *mon_get_current_bank_name(MEMSPACE mem)
{
    const char **bnp = NULL;

    if (!mon_interfaces[mem]->mem_bank_list) {
        return NULL;
    }

    bnp = mon_interfaces[mem]->mem_bank_list();
    while (*bnp) {
        if (mon_interfaces[mem]->mem_bank_from_name(*bnp) == mon_interfaces[mem]->current_bank) {
            return *bnp;
        }
        bnp++;
    }
    return NULL;
}

/*
    main entry point for the monitor to read a value from memory

    mem_bank_peek and mem_bank_read are set up in src/drive/drivecpu.c,
    src/mainc64cpu.c:358, src/mainviccpu.c:237, src/maincpu.c:296
*/

BYTE mon_get_mem_val_ex(MEMSPACE mem, int bank, WORD mem_addr)
{
    if (monitor_diskspace_dnr(mem) >= 0) {
        if (!check_drive_emu_level_ok(monitor_diskspace_dnr(mem) + 8)) {
            return 0;
        }
    }

    if ((sidefx == 0) && (mon_interfaces[mem]->mem_bank_peek != NULL)) {
        return mon_interfaces[mem]->mem_bank_peek(bank, mem_addr, mon_interfaces[mem]->context);
    } else {
        return mon_interfaces[mem]->mem_bank_read(bank, mem_addr, mon_interfaces[mem]->context);
    }
}

BYTE mon_get_mem_val(MEMSPACE mem, WORD mem_addr)
{
    return mon_get_mem_val_ex(mem, mon_interfaces[mem]->current_bank, mem_addr);
}

void mon_get_mem_block_ex(MEMSPACE mem, int bank, WORD start, WORD end, BYTE *data)
{
    int i;
    for(i=0;i<=end;i++) {
        data[i] = mon_get_mem_val_ex(mem, bank, (WORD)(start+i));
    }
}

void mon_get_mem_block(MEMSPACE mem, WORD start, WORD end, BYTE *data)
{
    mon_get_mem_block_ex(mem, mon_interfaces[mem]->current_bank, start, end, data);
}

void mon_set_mem_val(MEMSPACE mem, WORD mem_addr, BYTE val)
{
    int bank;

    bank = mon_interfaces[mem]->current_bank;

    if (monitor_diskspace_dnr(mem) >= 0)
        if (!check_drive_emu_level_ok(monitor_diskspace_dnr(mem) + 8))
            return;

    mon_interfaces[mem]->mem_bank_write(bank, mem_addr, val,
                                        mon_interfaces[mem]->context);
}

void mon_jump(MON_ADDR addr)
{
    mon_evaluate_default_addr(&addr);
    (monitor_cpu_for_memspace[addr_memspace(addr)]->mon_register_set_val)(addr_memspace(addr), e_PC,
                                            (WORD)(addr_location(addr)));
    exit_mon = 1;
}

void mon_keyboard_feed(const char *string)
{
    kbdbuf_feed_string(string);
}

/* *** ULTILITY FUNCTIONS *** */

void mon_print_bin(int val, char on, char off)
{
    int divisor;
    char digit;

    if (val > 0xfff)
        divisor = 0x8000;
    else if (val > 0xff)
        divisor = 0x800;
    else
        divisor = 0x80;

    while (divisor) {
        digit = (val & divisor) ? on : off;
        mon_out("%c",digit);
        if (divisor == 0x100)
            mon_out(" ");
        divisor /= 2;
    }
}

static void print_hex(int val)
{
    mon_out(val > 0xff ? "$%04x\n" : "$%02x\n", val);
}

static void print_octal(int val)
{
    mon_out(val > 0777 ? "0%06o\n" : "0%03o\n", val);
}


void mon_print_convert(int val)
{
    mon_out("+%d\n", val);
    print_hex(val);
    print_octal(val);
    mon_print_bin(val,'1','0');
    mon_out("\n");
}

void mon_add_number_to_buffer(int number)
{
    unsigned int i = data_buf_len;
    data_buf[data_buf_len++] = (number & 0xff);
    if (number > 0xff)
        data_buf[data_buf_len++] = ( (number>>8) & 0xff);
    data_buf[data_buf_len] = '\0';

    for (; i < data_buf_len; i++)
      data_mask_buf[i]=0xff;
}

void mon_add_number_masked_to_buffer(int number, int mask)
{
    data_buf[data_buf_len] = (number & 0xff);
    data_mask_buf[data_buf_len] = mask;
    data_buf_len++;
    data_buf[data_buf_len] = '\0';
}

void mon_add_string_to_buffer(char *str)
{
    unsigned int i = data_buf_len;
    strcpy((char *) &(data_buf[data_buf_len]), str);
    data_buf_len += (unsigned int)strlen(str);
    data_buf[data_buf_len] = '\0';
    lib_free(str);

    for (; i < data_buf_len; i++)
      data_mask_buf[i]=0xff;
}

static monitor_cpu_type_list_t *monitor_list_new(void)
{
    return (monitor_cpu_type_list_t *)lib_malloc(
        sizeof(monitor_cpu_type_list_t));
}

static void montor_list_destroy(monitor_cpu_type_list_t *list)
{
    lib_free(list);
}

void mon_backtrace(void)
{
    BYTE opc;
    WORD sp, i, addr, n;

    /* TODO support DTV stack relocation, check memspace handling, move somewhere else */
    n = 0;
    sp = (monitor_cpu_for_memspace[default_memspace]->mon_register_get_val)(default_memspace, e_SP);
    for (i = sp + 0x100 + 1; i < 0x1ff; i++) {
        addr = mon_get_mem_val(default_memspace, i);
        addr += ((WORD)mon_get_mem_val(default_memspace, (WORD)(i + 1))) << 8;
        addr -= 2;
        opc = mon_get_mem_val(default_memspace, addr);
        if (opc == 0x20 /* JSR */) {
            mon_out("(%d) %04x\n", n, addr);
        }
        n++;
    }
}

/* TODO move somewhere else */
cpuhistory_t cpuhistory[CPUHISTORY_SIZE];
int cpuhistory_i;

void monitor_cpuhistory_store(unsigned int addr, unsigned int op,
                              unsigned int p1, unsigned int p2,
                              BYTE reg_a,
                              BYTE reg_x,
                              BYTE reg_y,
                              BYTE reg_sp,
                              unsigned int reg_st)
{
    ++cpuhistory_i;
    cpuhistory_i &= (CPUHISTORY_SIZE-1);
    cpuhistory[cpuhistory_i].addr = addr;
    cpuhistory[cpuhistory_i].op = op;
    cpuhistory[cpuhistory_i].p1 = p1;
    cpuhistory[cpuhistory_i].p2 = p2;
    cpuhistory[cpuhistory_i].reg_a = reg_a;
    cpuhistory[cpuhistory_i].reg_x = reg_x;
    cpuhistory[cpuhistory_i].reg_y = reg_y;
    cpuhistory[cpuhistory_i].reg_sp = reg_sp;
    cpuhistory[cpuhistory_i].reg_st = reg_st;
}

/*#define TEST(x) ((x)!=0)*/

void mon_cpuhistory(int count)
{
#ifdef FEATURE_CPUMEMHISTORY
    BYTE op, p1, p2, p3 = 0;
    MEMSPACE mem;
    WORD loc, addr;
    int hex_mode = 1;
    const char *dis_inst;
    unsigned opc_size;
    int i, pos;

    if ((count<1)||(count>CPUHISTORY_SIZE)) {
        count = CPUHISTORY_SIZE;
    }

    pos = (cpuhistory_i + 1 - count) & (CPUHISTORY_SIZE-1);

    for (i=0; i < count; ++i) {
        addr = cpuhistory[pos].addr;
        op = cpuhistory[pos].op;
        p1 = cpuhistory[pos].p1;
        p2 = cpuhistory[pos].p2;

        mem = addr_memspace(addr);
        loc = addr_location(addr);

        dis_inst = mon_disassemble_to_string_ex(mem, loc, op, p1, p2, p3, hex_mode,
                                                &opc_size);

        /* Print the disassembled instruction */
        mon_out("%04x  %-30s - A:%02X Y:%02X Y:%02X SP:%02x %c%c-%c%c%c%c%c\n",
            loc, dis_inst,
            cpuhistory[pos].reg_a, cpuhistory[pos].reg_x, cpuhistory[pos].reg_y, cpuhistory[pos].reg_sp,
            ((cpuhistory[pos].reg_st & (1<<7))!=0)?'N':' ',
            ((cpuhistory[pos].reg_st & (1<<6))!=0)?'V':' ',
            ((cpuhistory[pos].reg_st & (1<<4))!=0)?'B':' ',
            ((cpuhistory[pos].reg_st & (1<<3))!=0)?'D':' ',
            ((cpuhistory[pos].reg_st & (1<<2))!=0)?'I':' ',
            ((cpuhistory[pos].reg_st & (1<<1))!=0)?'Z':' ',
            ((cpuhistory[pos].reg_st & (1<<0))!=0)?'C':' '
		);

        pos = (pos+1) & (CPUHISTORY_SIZE-1);
    }
#else
    mon_out("Disabled. configure with --enable-memmap and recompile.\n");
#endif
}


/* TODO move somewhere else */
BYTE *mon_memmap;
int mon_memmap_size;
int mon_memmap_picx;
int mon_memmap_picy;
BYTE memmap_state;

static void mon_memmap_init(void)
{
#ifdef FEATURE_CPUMEMHISTORY
    mon_memmap_picx = 0x100;
    if (machine_class == VICE_MACHINE_C64DTV) {
        mon_memmap_picy = 0x2000;
    } else {
        mon_memmap_picy = 0x100;
    }
    mon_memmap_size = mon_memmap_picx * mon_memmap_picy;
    mon_memmap = lib_malloc(mon_memmap_size);
#else
    mon_memmap = NULL;
    mon_memmap_size = 0;
    mon_memmap_picx = 0;
    mon_memmap_picy = 0;
#endif
}

void mon_memmap_zap(void)
{
#ifdef FEATURE_CPUMEMHISTORY
    memset(mon_memmap, 0, mon_memmap_size);
#else
    mon_out("Disabled. configure with --enable-memmap and recompile.\n");
#endif
}

void mon_memmap_show(int mask, MON_ADDR start_addr, MON_ADDR end_addr)
{
#ifdef FEATURE_CPUMEMHISTORY
    unsigned int i;
    BYTE b;

    if (machine_class == VICE_MACHINE_C64DTV) {
       mon_out("  addr: IO ROM RAM\n");
    } else {
       mon_out("addr: IO ROM RAM\n");
    }

    if (start_addr == BAD_ADDR) start_addr = 0;
    if (end_addr == BAD_ADDR) end_addr = mon_memmap_size-1;
    if (start_addr>end_addr) start_addr = end_addr;

    for (i = start_addr; i <= end_addr; ++i) {
        b = mon_memmap[i];
        if ((b & mask)!= 0) {
            if (machine_class == VICE_MACHINE_C64DTV) {
                mon_out("%06x: %c%c %c%c%c %c%c%c\n",i,
                    (b&MEMMAP_I_O_R)?'r':'-',
                    (b&MEMMAP_I_O_W)?'w':'-',
                    (b&MEMMAP_ROM_R)?'r':'-',
                    (b&MEMMAP_ROM_W)?'w':'-',
                    (b&MEMMAP_ROM_X)?'x':'-',
                    (b&MEMMAP_RAM_R)?'r':'-',
                    (b&MEMMAP_RAM_W)?'w':'-',
                    (b&MEMMAP_RAM_X)?'x':'-');
            } else {
                mon_out("%04x: %c%c %c%c%c %c%c%c\n",i,
                    (b&MEMMAP_I_O_R)?'r':'-',
                    (b&MEMMAP_I_O_W)?'w':'-',
                    (b&MEMMAP_ROM_R)?'r':'-',
                    (b&MEMMAP_ROM_W)?'w':'-',
                    (b&MEMMAP_ROM_X)?'x':'-',
                    (b&MEMMAP_RAM_R)?'r':'-',
                    (b&MEMMAP_RAM_W)?'w':'-',
                    (b&MEMMAP_RAM_X)?'x':'-');
            }
        }
    }
#else
    mon_out("Disabled. configure with --enable-memmap and recompile.\n");
#endif
}

void monitor_memmap_store(unsigned int addr, unsigned int type)
{
    BYTE op = cpuhistory[cpuhistory_i].op;

    if (inside_monitor) return;

    /* Ignore reg_pc+2 reads on branches & JSR
       and return address read on RTS */
    if (type & (MEMMAP_ROM_R|MEMMAP_RAM_R)
      &&(((op & 0x1f) == 0x10)||(op == OP_JSR)
      ||((op == OP_RTS) && ((addr>0x1ff)||(addr<0x100)))))
        return;

    mon_memmap[addr & (mon_memmap_size-1)] |= type;
}

#ifdef FEATURE_CPUMEMHISTORY
BYTE mon_memmap_palette[256*3];

void mon_memmap_make_palette(void)
{
    int i;
    for (i=0; i<256; ++i) {
        mon_memmap_palette[i*3+0] = (i&(MEMMAP_RAM_W))?0x80:0+(i&(MEMMAP_ROM_W))?0x60:0+(i&(MEMMAP_I_O_W))?0x1f:0;
        mon_memmap_palette[i*3+1] = (i&(MEMMAP_RAM_X))?0x80:0+(i&(MEMMAP_ROM_X))?0x60:0+(i&(MEMMAP_I_O_W|MEMMAP_I_O_R))?0x1f:0;
        mon_memmap_palette[i*3+2] = (i&(MEMMAP_RAM_R))?0x80:0+(i&(MEMMAP_ROM_R))?0x60:0+(i&(MEMMAP_I_O_R))?0x1f:0;
    }
}
#endif

void mon_memmap_save(const char* filename, int format)
{
#ifdef FEATURE_CPUMEMHISTORY
    const char* drvname;

    switch(format) {
        case 1:
            drvname = "PCX";
            break;
        case 2:
            drvname = "PNG";
            break;
        case 3:
            drvname = "GIF";
            break;
        case 4:
            drvname = "IFF";
            break;
        default:
            drvname = "BMP";
            break;
    }
    if (memmap_screenshot_save(drvname, filename, mon_memmap_picx, mon_memmap_picy, mon_memmap, mon_memmap_palette)) {
        mon_out("Failed.\n");
    }
#else
    mon_out("Disabled. configure with --enable-memmap and recompile.\n");
#endif
}

void mon_screenshot_save(const char* filename, int format)
{
    const char* drvname;

    switch(format) {
        case 1:
            drvname = "PCX";
            break;
        case 2:
            drvname = "PNG";
            break;
        case 3:
            drvname = "GIF";
            break;
        case 4:
            drvname = "IFF";
            break;
        default:
            drvname = "BMP";
            break;
    }
    if (screenshot_save(drvname, filename, machine_video_canvas_get(0))) {
        mon_out("Failed.\n");
    }
}

void mon_show_pwd(void)
{
    mon_out("%s\n", ioutil_current_dir());
}

void mon_show_dir(const char *path)
{
    struct ioutil_dir_s *dir;
    char *name;
    char *mpath;
    char *fullname;

    if (path) {
        mpath=(char *)path;
    } else {
        mpath=ioutil_current_dir();
    }
    mon_out("Displaying directory: `%s'\n", mpath);

    dir = ioutil_opendir(mpath);
    if (!dir) {
        mon_out("Couldn't open directory.\n");
        return;
    }

    while ( (name = ioutil_readdir(dir)) ) {
        unsigned int len, isdir;
        int ret;
        if (path) {
            fullname = util_concat(path, FSDEV_DIR_SEP_STR, name, NULL);
            ret = ioutil_stat(fullname, &len, &isdir);
            lib_free(fullname);
        } else {
            ret = ioutil_stat(name, &len, &isdir);
        }
        if (!ret) {
            if (isdir)
                mon_out("     <dir> %s\n", name);
            else
                mon_out("%10d %s\n", len, name);
        } else
            mon_out("%-20s?????\n", name);
    }
    ioutil_closedir(dir);
}

void mon_resource_get(const char *name)
{
    switch(resources_query_type(name)) {
        case RES_INTEGER:
        case RES_STRING:
            mon_out("%s\n",resources_write_item_to_string(name,""));
            break;
        default:
            mon_out("Unknown resource \"%s\".\n",name);
            return;
    }
}

void mon_resource_set(const char *name, const char* value)
{
    switch(resources_query_type(name)) {
        case RES_INTEGER:
        case RES_STRING:
            if (resources_set_value_string(name,value)) {
                mon_out("Failed.\n");
            }
            ui_update_menus();
            break;
        default:
            mon_out("Unknown resource \"%s\".\n",name);
            return;
    }
}

void mon_reset_machine(int type)
{
    switch(type) {
        case 1:
            machine_trigger_reset(MACHINE_RESET_MODE_HARD);
            exit_mon = 1;
            break;
        case 8:
        case 9:
        case 10:
        case 11:
            drivecpu_trigger_reset(type-8);
            break;
        default:
            machine_trigger_reset(MACHINE_RESET_MODE_SOFT);
            exit_mon = 1;
            break;
    }
}

void mon_tape_ctrl(int command)
{
    if ((command<0)||(command>6)) {
        mon_out("Unknown command.\n");
    } else {
        datasette_control(command);
    }
}

void mon_cart_freeze(void)
{
    if (mon_cart_cmd.cartridge_trigger_freeze != NULL) {
        (mon_cart_cmd.cartridge_trigger_freeze)();
    } else {
        mon_out("Unsupported.\n");
    }
}

void mon_export(void)
{
    if (mon_cart_cmd.export_dump != NULL) {
        (mon_cart_cmd.export_dump)();
    } else {
        mon_out("Unsupported.\n");
    }
}

void mon_stopwatch_show(const char* prefix, const char* suffix)
{
    unsigned long t;
    monitor_interface_t* interface;
    interface = mon_interfaces[default_memspace];
    t = (unsigned long)
            (*interface->clk - stopwatch_start_time[default_memspace]);
    mon_out("%s%10lu%s", prefix, t, suffix);
}

void mon_stopwatch_reset(void)
{
    monitor_interface_t* interface;
    interface = mon_interfaces[default_memspace];
    stopwatch_start_time[default_memspace] = *interface->clk;
    mon_out("Stopwatch reset to 0.\n");
}

/* Local helper functions for building the lists */
static monitor_cpu_type_t* find_monitor_cpu_type(CPU_TYPE_t cputype)
{
    monitor_cpu_type_list_t *list_ptr=monitor_cpu_type_list;
    while (list_ptr->monitor_cpu_type.cpu_type != cputype) {
        list_ptr = list_ptr->next_monitor_cpu_type;
        if (!list_ptr) {
            return NULL;
        }
    }
    return &(list_ptr->monitor_cpu_type);
}

static void add_monitor_cpu_type_supported(supported_cpu_type_list_t **list_ptr, monitor_cpu_type_t *mon_cpu_type)
{
    supported_cpu_type_list_t *element_ptr;
    if (mon_cpu_type) {
        element_ptr=lib_malloc(sizeof(supported_cpu_type_list_t));
        element_ptr->next=*list_ptr;
        element_ptr->monitor_cpu_type_p=mon_cpu_type;
        *list_ptr=element_ptr;
    }
}

static void find_supported_monitor_cpu_types(supported_cpu_type_list_t **list_ptr, monitor_interface_t *mon_interface)
{
    if (mon_interface->h6809_cpu_regs) {
        add_monitor_cpu_type_supported(list_ptr, find_monitor_cpu_type(CPU_6809));
    }
    if (mon_interface->z80_cpu_regs) {
        add_monitor_cpu_type_supported(list_ptr, find_monitor_cpu_type(CPU_Z80));
    }
    if (mon_interface->dtv_cpu_regs) {
        add_monitor_cpu_type_supported(list_ptr, find_monitor_cpu_type(CPU_6502DTV));
    }
    if (mon_interface->cpu_regs) {
        add_monitor_cpu_type_supported(list_ptr, find_monitor_cpu_type(CPU_6502));
    }
}

/* *** MISC COMMANDS *** */

monitor_cpu_type_t* monitor_find_cpu_type_from_string(const char *cpu_type)
{
    int cpu;
    cpu=find_cpu_type_from_string(cpu_type);
    if (cpu<0)
        return NULL;
    return find_monitor_cpu_type(cpu);
}

void monitor_init(monitor_interface_t *maincpu_interface_init,
                  monitor_interface_t *drive_interface_init[],
                  monitor_cpu_type_t **asmarray)
{
    int i, j;
    unsigned int dnr;
    monitor_cpu_type_list_t *monitor_cpu_type_list_ptr;

    mon_yydebug = 0;
    sidefx = e_OFF;
    default_radix = e_hexadecimal;
    default_memspace = e_comp_space;
    instruction_count = 0;
    skip_jsrs = FALSE;
    wait_for_return_level = 0;
    trigger_break_on_next_instruction = FALSE;
    mon_breakpoint_init();
    data_buf_len = 0;
    asm_mode = 0;
    next_or_step_stop = 0;
    recording = FALSE;
    cpuhistory_i = 0;

    mon_ui_init();

    monitor_cpu_type_list = monitor_list_new();
    monitor_cpu_type_list_ptr = monitor_cpu_type_list;

    i = 0;
    while (asmarray[i] != NULL) {
        memcpy(&(monitor_cpu_type_list_ptr->monitor_cpu_type),
               asmarray[i], sizeof(monitor_cpu_type_t));
        monitor_cpu_type_list_ptr->next_monitor_cpu_type = monitor_list_new();
        monitor_cpu_type_list_ptr
            = monitor_cpu_type_list_ptr->next_monitor_cpu_type;
        monitor_cpu_type_list_ptr->next_monitor_cpu_type = NULL;
        i++;
    }

    for (i=0;i<NUM_MEMSPACES;i++) {
        monitor_cpu_type_supported[i]=NULL;
    }
    /* We should really be told what CPUs are supported by each memspace, but that will
     * require a bunch of changes, so for now we detect it based on the available registers. */
    find_supported_monitor_cpu_types(&monitor_cpu_type_supported[e_comp_space], maincpu_interface_init);

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        find_supported_monitor_cpu_types(&monitor_cpu_type_supported[monitor_diskspace_mem(dnr)],
                                         drive_interface_init[dnr]);
    }

    /* Build array of pointers to monitor_cpu_type structs */
    monitor_cpu_for_memspace[e_comp_space]=
        monitor_cpu_type_supported[e_comp_space]->monitor_cpu_type_p;
    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        monitor_cpu_for_memspace[monitor_diskspace_mem(dnr)]=
            monitor_cpu_type_supported[monitor_diskspace_mem(dnr)]->monitor_cpu_type_p;
    }
    /* Safety precaution */
    monitor_cpu_for_memspace[e_default_space]=monitor_cpu_for_memspace[e_comp_space];

    watch_load_occurred = FALSE;
    watch_store_occurred = FALSE;

    for (i = 1; i < NUM_MEMSPACES; i++) {
        dot_addr[i] = new_addr(e_default_space + i, 0);
        watch_load_count[i] = 0;
        watch_store_count[i] = 0;
        monitor_mask[i] = MI_NONE;
        monitor_labels[i].name_list = NULL;
        for (j = 0; j < HASH_ARRAY_SIZE; j++)
            monitor_labels[i].addr_hash_table[j] = NULL;
    }

    default_memspace = e_comp_space;

    asm_mode_addr = BAD_ADDR;

    mon_interfaces[e_comp_space] = maincpu_interface_init;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++)
        mon_interfaces[monitor_diskspace_mem(dnr)] = drive_interface_init[dnr];

    mon_memmap_init();
#ifdef FEATURE_CPUMEMHISTORY
    mon_memmap_zap();
    mon_memmap_make_palette();
#endif

    if (mon_init_break != -1)
        mon_breakpoint_add_checkpoint((WORD)mon_init_break, BAD_ADDR, TRUE, e_exec, FALSE);

    if (playback > 0) {
        playback_commands(playback);
    }
}

void monitor_shutdown(void)
{
    monitor_cpu_type_list_t *list, *list_next;
    supported_cpu_type_list_t *slist, *slist_next;
    int i;

    list = monitor_cpu_type_list;

    while (list != NULL) {
        list_next = list->next_monitor_cpu_type;
        montor_list_destroy(list);
        list = list_next;
    }
    for (i=0; i < NUM_MEMSPACES; i++) {
        slist = monitor_cpu_type_supported[i];
        while (slist != NULL) {
            slist_next = slist->next;
            lib_free(slist);
            slist = slist_next;
        }
    }

#ifdef FEATURE_CPUMEMHISTORY
   lib_free(mon_memmap);
#endif
}

static int monitor_set_initial_breakpoint(const char *param, void *extra_param)
{
    int val;

    val = strtoul(param, NULL, 0);
    if (val >= 0 && val < 65536)
        mon_init_break = val;

    return 0;
}

static const cmdline_option_t cmdline_options[] = {
    { "-moncommands", CALL_FUNCTION, 1,
      set_playback_name, NULL, NULL, NULL,
      USE_PARAM_ID, USE_DESCRIPTION_ID,
      IDCLS_P_NAME, IDCLS_EXECUTE_MONITOR_FROM_FILE,
      NULL, NULL },
    { "-initbreak", CALL_FUNCTION, 1,
      monitor_set_initial_breakpoint, NULL, NULL, NULL,
      USE_PARAM_ID, USE_DESCRIPTION_ID,
      IDCLS_P_VALUE, IDCLS_SET_INITIAL_BREAKPOINT,
      NULL, NULL },
    { NULL }
};

int monitor_cmdline_options_init(void)
{
    mon_cart_cmd.cartridge_attach_image = NULL;
    mon_cart_cmd.cartridge_detach_image = NULL;
    mon_cart_cmd.cartridge_trigger_freeze = NULL;
    mon_cart_cmd.cartridge_trigger_freeze_nmi_only = NULL;

    return cmdline_register_options(cmdline_options);
}

monitor_interface_t *monitor_interface_new(void)
{
    return (monitor_interface_t *)lib_calloc(sizeof(monitor_interface_t), 1);
}

void monitor_interface_destroy(monitor_interface_t *monitor_interface)
{
    lib_free(monitor_interface);
}

void mon_start_assemble_mode(MON_ADDR addr, char *asm_line)
{
    asm_mode = 1;

    mon_evaluate_default_addr(&addr);
    asm_mode_addr = addr;
    if (asm_line) {
        parse_and_execute_line(asm_line);
    }
}

void mon_exit_assemble_mode(void)
{
    asm_mode = 0;
}

/* ------------------------------------------------------------------------- */

/* Memory.  */

void mon_display_screen(void)
{
    WORD base;
    BYTE rows, cols;
    unsigned int r, c;
    int bank;

    mem_get_screen_parameter(&base, &rows, &cols, &bank);
    /* We need something like bankname = something(e_comp_space, bank) here */
    mon_out("Displaying %dx%d screen at $%04x:\n", cols, rows, base);

    for (r = 0; r < rows; r++) {
        for (c = 0; c < cols; c++) {
            BYTE data;

            /* Not sure this really neads to use mon_get_mem_val_ex()
               Do we want monitor sidefx in a function that's *supposed*
               to just read from screen memory? */
            data = mon_get_mem_val_ex(e_comp_space, bank, (WORD)ADDR_LIMIT(base++));
            data = charset_p_toascii(charset_screencode_to_petcii(data), 1);

            mon_out("%c", data);
        }
        mon_out("\n");
    }
}

/*
    display io regs

    if addr = 0 display full list, no details
    if addr = 1 display full list, with details

    for other addr display full details for respective device
*/
void mon_display_io_regs(MON_ADDR addr)
{
    mem_ioreg_list_t *mem_ioreg_list_base;
    unsigned int n;
    MON_ADDR start,end;
    int newbank = 0;
    int currbank = mon_interfaces[default_memspace]->current_bank;

    if (mon_interfaces[default_memspace]->mem_bank_list) {
        newbank = mon_interfaces[default_memspace]->mem_bank_from_name("io");
    }

    if (newbank >= 0) {
        mon_interfaces[default_memspace]->current_bank = newbank;
    }

    mem_ioreg_list_base
        = mon_interfaces[default_memspace]->mem_ioreg_list_get(
            mon_interfaces[default_memspace]->context);
    n = 0;

    if (mem_ioreg_list_base) {
        while (1) {
            start = mem_ioreg_list_base[n].start;
            end = mem_ioreg_list_base[n].end;

            if ((addr < 2) || ((addr >= start) && (addr <= end))) {
                if ((addr == 1) && (n > 0)) {
                    mon_out("\n");
                }
                start = new_addr(default_memspace, start);
                end = new_addr(default_memspace, end);
                mon_out("%s:\n", mem_ioreg_list_base[n].name);
                mon_memory_display(e_hexadecimal, start, end, DF_PETSCII);

                if (addr > 0) {
                    if (mem_ioreg_list_base[n].dump) {
                        mon_out("\n");
                        if (mem_ioreg_list_base[n].dump((WORD)(addr_location(start))) < 0) {
                            mon_out("No details available.\n");
                        }
                    } else {
                        mon_out("No details available.\n");
                    }
                }
            }

            if (mem_ioreg_list_base[n].next == 0) {
                break;
            }
            n++;
        }
    } else {
        mon_out("No I/O regs available\n");
    }

    mon_interfaces[default_memspace]->current_bank = currbank;
    lib_free(mem_ioreg_list_base);
}

void mon_ioreg_add_list(mem_ioreg_list_t **list, const char *name,
                        int start_, int end_, void *dump)
{
    mem_ioreg_list_t *base;
    unsigned int n;
    WORD start = start_ & 0xFFFFu;
    WORD end = end_ & 0xFFFFu;

    assert(start == start_);
    assert(end == end_);

    base = *list;
    n = 0;

    while (base != NULL) {
        n++;
        if (base[n - 1].next == 0)
            break;
    }

    base = lib_realloc(base, sizeof(mem_ioreg_list_t)
           * (n + 1));

    if (n > 0)
        base[n - 1].next = 1;

    base[n].name = name;
    base[n].start = start;
    base[n].end = end;
    base[n].dump = dump;
    base[n].next = 0;

    *list = base;
}


/* *** FILE COMMANDS *** */

void mon_change_dir(const char *path)
{
    if (ioutil_chdir((char*)path) < 0)
        mon_out("Cannot change to directory `%s':\n", path);

    mon_out("Changing to directory: `%s'\n", path);
}

void mon_save_symbols(MEMSPACE mem, const char *filename)
{
    FILE *fp;
    symbol_entry_t *sym_ptr;

    if (NULL == (fp = fopen(filename, MODE_WRITE))) {
        mon_out("Saving for `%s' failed.\n", filename);
        return;
    }

    mon_out("Saving symbol table to `%s'...\n", filename);

    /* FIXME: Write out all memspaces? */
    if (mem == e_default_space)
       mem = default_memspace;

    sym_ptr = monitor_labels[mem].name_list;

    while (sym_ptr) {
        fprintf(fp, "al %s:%04x %s\n", mon_memspace_string[mem], sym_ptr->addr,
                sym_ptr->name);
        sym_ptr = sym_ptr->next;
    }

    fclose(fp);
}


/* *** COMMAND FILES *** */


void mon_record_commands(char *filename)
{
    if (recording) {
        mon_out("Recording already in progress. Use 'stop' to end recording.\n");
        return;
    }

    recording_name = filename;

    if (NULL == (recording_fp = fopen(recording_name, MODE_WRITE))) {
        mon_out("Cannot create `%s'.\n", recording_name);
        return;
    }

    setbuf(recording_fp, NULL);

    recording = TRUE;
}

void mon_end_recording(void)
{
    if (!recording) {
        mon_out("No file is currently being recorded.\n");
        return;
    }

    fclose(recording_fp);
    mon_out("Closed file %s.\n", recording_name);
    recording = FALSE;
}

static int set_playback_name(const char *param, void *extra_param)
{
    if (!playback_name) {
        playback_name = lib_stralloc(param);
        playback = 1;
    }
    return 0;
}

static void playback_commands(int current_playback)
{
    FILE *fp;
    char string[256];
    char *filename = playback_name;

    fp = fopen(filename, MODE_READ_TEXT);

    if (fp == NULL)
        fp = sysfile_open(filename, NULL, MODE_READ_TEXT);

    if (fp == NULL) {
        mon_out("Playback for `%s' failed.\n", filename);
        lib_free(playback_name);
        playback_name = NULL;
        --playback;
        return;
    }

    lib_free(playback_name);
    playback_name = NULL;

    while (fgets(string, 255, fp) != NULL) {
        if (strcmp(string, "stop\n") == 0)
            break;

        string[strlen(string) - 1] = '\0';
        parse_and_execute_line(string);

        if (playback > current_playback) {
            playback_commands(playback);
        }
    }

    fclose(fp);
    --playback;
}

void mon_playback_init(const char *filename)
{
    if (playback < MAX_PLAYBACK) {
        playback_name = lib_stralloc(filename);
        ++playback;
    } else {
        mon_out("Playback for `%s' failed (recursion > %i).\n", filename, MAX_PLAYBACK);
    }
}


/* *** SYMBOL TABLE *** */


static void free_symbol_table(MEMSPACE mem)
{
    symbol_entry_t *sym_ptr, *temp;
    int i;

    /* Remove name list */
    sym_ptr = monitor_labels[mem].name_list;
    while (sym_ptr) {
        /* Name memory is freed below. */
        temp = sym_ptr;
        sym_ptr = sym_ptr->next;
        lib_free(temp);
    }

    /* Remove address hash table */
    for (i = 0; i < HASH_ARRAY_SIZE; i++) {
        sym_ptr = monitor_labels[mem].addr_hash_table[i];
        while (sym_ptr) {
            lib_free (sym_ptr->name);
            temp = sym_ptr;
            sym_ptr = sym_ptr->next;
            lib_free(temp);
        }
    }
}

char *mon_symbol_table_lookup_name(MEMSPACE mem, WORD addr)
{
    symbol_entry_t *sym_ptr;

    if (mem == e_default_space)
        mem = default_memspace;

    sym_ptr = monitor_labels[mem].addr_hash_table[HASH_ADDR(addr)];
    while (sym_ptr) {
        if (addr == sym_ptr->addr)
            return sym_ptr->name;
        sym_ptr = sym_ptr->next;
    }

    return NULL;
}

int mon_symbol_table_lookup_addr(MEMSPACE mem, char *name)
{
    symbol_entry_t *sym_ptr;

    if (mem == e_default_space)
        mem = default_memspace;

    if (strcmp(name, ".PC") == 0) {
        return (monitor_cpu_for_memspace[mem]->mon_register_get_val)(mem, e_PC);
    }

    sym_ptr = monitor_labels[mem].name_list;
    while (sym_ptr) {
        if (strcmp(sym_ptr->name, name) == 0)
            return sym_ptr->addr;
        sym_ptr = sym_ptr->next;
    }

    return -1;
}

char* mon_prepend_dot_to_name(char* name)
{
    char* s = malloc(strlen(name) + 2);
    strcpy(s, ".");
    strcat(s, name);
    free(name);
    return s;
}

void mon_add_name_to_symbol_table(MON_ADDR addr, char *name)
{
    symbol_entry_t *sym_ptr;
    char *old_name;
    int old_addr;
    MEMSPACE mem = addr_memspace(addr);
    WORD loc = addr_location(addr);

    if (strcmp(name, ".PC") == 0) {
        mon_out("Error: .PC is a reserved label.\n");
        return;
    }

    if (mem == e_default_space)
        mem = default_memspace;

    old_name = mon_symbol_table_lookup_name(mem, loc);
    old_addr = mon_symbol_table_lookup_addr(mem, name);
    if (old_name && (WORD)(old_addr) != addr ) {
        mon_out("Warning: label(s) for address $%04x already exist.\n",
                  loc);
    }
    if (old_addr >= 0 && old_addr != loc) {
        mon_out("Changing address of label %s from $%04x to $%04x\n",
                  name, old_addr, loc);
        mon_remove_name_from_symbol_table(mem, name);
    }

    /* Add name to name list */
    sym_ptr = lib_malloc(sizeof(symbol_entry_t));
    sym_ptr->name = name;
    sym_ptr->addr = loc;

    sym_ptr->next = monitor_labels[mem].name_list;
    monitor_labels[mem].name_list = sym_ptr;

    /* Add address to hash table */
    sym_ptr = lib_malloc(sizeof(symbol_entry_t));
    sym_ptr->name = name;
    sym_ptr->addr = addr;

    sym_ptr->next = monitor_labels[mem].addr_hash_table[HASH_ADDR(loc)];
    monitor_labels[mem].addr_hash_table[HASH_ADDR(loc)] = sym_ptr;
}

void mon_remove_name_from_symbol_table(MEMSPACE mem, char *name)
{
    int addr;
    symbol_entry_t *sym_ptr, *prev_ptr;

    if (mem == e_default_space)
        mem = default_memspace;

    if (name == NULL) {
        /* FIXME - prompt user */
        free_symbol_table(mem);
        return;
    }

    if ( (addr = mon_symbol_table_lookup_addr(mem, name)) < 0) {
        mon_out("Symbol %s not found.\n", name);
        return;
    }

    /* Remove entry in name list */
    sym_ptr = monitor_labels[mem].name_list;
    prev_ptr = NULL;
    while (sym_ptr) {
        if (strcmp(sym_ptr->name, name) == 0) {
            /* Name memory is freed below. */
            addr = sym_ptr->addr;
            if (prev_ptr)
                prev_ptr->next = sym_ptr->next;
            else
                monitor_labels[mem].name_list = NULL;
            lib_free(sym_ptr);
            break;
        }
        prev_ptr = sym_ptr;
        sym_ptr = sym_ptr->next;
    }

    /* Remove entry in address hash table */
    sym_ptr = monitor_labels[mem].addr_hash_table[HASH_ADDR(addr)];
    prev_ptr = NULL;
    while (sym_ptr) {
        if (addr == sym_ptr->addr) {
            lib_free(sym_ptr->name);
            if (prev_ptr)
                prev_ptr->next = sym_ptr->next;
            else
                monitor_labels[mem].addr_hash_table[HASH_ADDR(addr)] = NULL;
            lib_free(sym_ptr);
            return;
        }
        prev_ptr = sym_ptr;
        sym_ptr = sym_ptr->next;
    }
}

void mon_print_symbol_table(MEMSPACE mem)
{
    symbol_entry_t *sym_ptr;

    if (mem == e_default_space)
        mem = default_memspace;

    sym_ptr = monitor_labels[mem].name_list;
    while (sym_ptr) {
        mon_out("$%04x %s\n",sym_ptr->addr, sym_ptr->name);
        sym_ptr = sym_ptr->next;
    }
}


/* *** INSTRUCTION COMMANDS *** */


void mon_instructions_step(int count)
{
    if (count >= 0) {
        mon_out("Stepping through the next %d instruction(s).\n", count);
    }
    instruction_count = (count >= 0) ? count : 1;
    wait_for_return_level = 0;
    skip_jsrs = FALSE;
    exit_mon = 1;

    if (instruction_count == 1) {
        mon_console_close_on_leaving = 0;
    }

    monitor_mask[default_memspace] |= MI_STEP;
    interrupt_monitor_trap_on(mon_interfaces[default_memspace]->int_status);
}

void mon_instructions_next(int count)
{
    if (count >= 0) {
        mon_out("Nexting through the next %d instruction(s).\n", count);
    }
    instruction_count = (count >= 0) ? count : 1;
    wait_for_return_level = 0;
    skip_jsrs = TRUE;
    exit_mon = 1;

    if (instruction_count == 1) {
        mon_console_close_on_leaving = 0;
    }

    monitor_mask[default_memspace] |= MI_STEP;
    interrupt_monitor_trap_on(mon_interfaces[default_memspace]->int_status);
}

void mon_instruction_return(void)
{
    instruction_count = 1;
    wait_for_return_level = 1;
    skip_jsrs = TRUE;
    exit_mon = 1;

    monitor_mask[default_memspace] |= MI_STEP;
    interrupt_monitor_trap_on(mon_interfaces[default_memspace]->int_status);
}

void mon_stack_up(int count)
{
    mon_out("Going up %d stack frame(s).\n",
              (count>=0)?count:1);
}

void mon_stack_down(int count)
{
    mon_out("Going down %d stack frame(s).\n",
              (count>=0)?count:1);
}


/* *** CONDITIONAL EXPRESSIONS *** */


void mon_print_conditional(cond_node_t *cnode)
{
    /* Do an in-order traversal of the tree */
    if (cnode->is_parenthized)
        mon_out("( ");

    if (cnode->operation != e_INV) {
        if (!(cnode->child1 && cnode->child2)) {
            log_error(LOG_ERR, "No conditional!");
            return;
        }
        mon_print_conditional(cnode->child1);
        mon_out(" %s ",cond_op_string[cnode->operation]);
        mon_print_conditional(cnode->child2);
    } else {
        if (cnode->is_reg)
            mon_out(".%s", register_string[reg_regid(cnode->reg_num)]);
        else
            mon_out("%d", cnode->value);
    }

    if (cnode->is_parenthized)
        mon_out(" )");
}


int mon_evaluate_conditional(cond_node_t *cnode)
{
    /* Do a post-order traversal of the tree */
    if (cnode->operation != e_INV) {
        if (!(cnode->child1 && cnode->child2)) {
            log_error(LOG_ERR, "No conditional!");
            return 0;
        }
        mon_evaluate_conditional(cnode->child1);
        mon_evaluate_conditional(cnode->child2);

        switch(cnode->operation) {
          case e_EQU:
            cnode->value = ((cnode->child1->value) == (cnode->child2->value));
            break;
          case e_NEQ:
            cnode->value = ((cnode->child1->value) != (cnode->child2->value));
            break;
          case e_GT :
            cnode->value = ((cnode->child1->value) > (cnode->child2->value));
            break;
          case e_LT :
            cnode->value = ((cnode->child1->value) < (cnode->child2->value));
            break;
          case e_GTE:
            cnode->value = ((cnode->child1->value) >= (cnode->child2->value));
            break;
          case e_LTE:
            cnode->value = ((cnode->child1->value) <= (cnode->child2->value));
            break;
          case e_AND:
            cnode->value = ((cnode->child1->value) && (cnode->child2->value));
            break;
          case e_OR :
            cnode->value = ((cnode->child1->value) || (cnode->child2->value));
            break;
          default:
            log_error(LOG_ERR, "Unexpected conditional operator: %d\n",
                      cnode->operation);
            return 0;
        }
    } else {
        if (cnode->is_reg)
            cnode->value = (monitor_cpu_for_memspace[reg_memspace(cnode->reg_num)]->mon_register_get_val)
                           (reg_memspace(cnode->reg_num),
                           reg_regid(cnode->reg_num));
    }

    return cnode->value;
}


void mon_delete_conditional(cond_node_t *cnode)
{
    if (!cnode)
        return;

    if (cnode->child1)
        mon_delete_conditional(cnode->child1);

    if (cnode->child2)
        mon_delete_conditional(cnode->child2);

    lib_free(cnode);
}


/* *** WATCHPOINTS *** */


void monitor_watch_push_load_addr(WORD addr, MEMSPACE mem)
{
    if (inside_monitor) {
        return;
    }

    if (watch_load_count[mem] == 9) {
         return;
    }

    watch_load_occurred = TRUE;
    watch_load_array[watch_load_count[mem]][mem] = addr;
    watch_load_count[mem]++;
}

void monitor_watch_push_store_addr(WORD addr, MEMSPACE mem)
{
    if (inside_monitor) {
        return;
    }

    if (watch_store_count[mem] == 9) {
        return;
    }

    watch_store_occurred = TRUE;
    watch_store_array[watch_store_count[mem]][mem] = addr;
    watch_store_count[mem]++;
}

static bool watchpoints_check_loads(MEMSPACE mem, unsigned int lastpc, unsigned int pc)
{
    bool trap = FALSE;
    unsigned count;
    WORD addr = 0;

    count = watch_load_count[mem];
    watch_load_count[mem] = 0;
    while (count) {
        count--;
        addr = watch_load_array[count][mem];
        if (mon_breakpoint_check_checkpoint(mem, addr, lastpc, e_load)) {
            trap = TRUE;
        }
    }
    return trap;
}

static bool watchpoints_check_stores(MEMSPACE mem, unsigned int lastpc, unsigned int pc)
{
    bool trap = FALSE;
    unsigned count;
    WORD addr = 0;

    count = watch_store_count[mem];
    watch_store_count[mem] = 0;

    while (count) {
        count--;
        addr = watch_store_array[count][mem];
        if (mon_breakpoint_check_checkpoint(mem, addr, lastpc, e_store)) {
            trap = TRUE;
        }
    }
    return trap;
}


/* *** CPU INTERFACES *** */


int monitor_force_import(MEMSPACE mem)
{
    bool result;

    result = force_array[mem];
    force_array[mem] = FALSE;

    return result;
}

/* called by cpu core */
void monitor_check_icount(WORD pc)
{
    if (trigger_break_on_next_instruction) {
        trigger_break_on_next_instruction = FALSE;
        if (monitor_mask[default_memspace] & MI_STEP) {
            monitor_mask[default_memspace] &= ~MI_STEP;
            disassemble_on_entry = 1;
        }
        if (!monitor_mask[default_memspace]) {
            interrupt_monitor_trap_off(mon_interfaces[default_memspace]->int_status);
        }

        monitor_startup(e_default_space);
    }

    if (!instruction_count) {
        return;
    }

    if (skip_jsrs == TRUE) {
        /*
            maintain the return level while "trace over"

            - if the current address is the start of a trap, the respective opcode
              is not actually executed and thus is ignored.
        */
        if ((default_memspace != e_comp_space) || (traps_checkaddr(pc) == 0)) {
            if (MONITOR_GET_OPCODE(default_memspace) == OP_JSR) {
                wait_for_return_level++;
            }
            if (MONITOR_GET_OPCODE(default_memspace) == OP_RTS) {
                wait_for_return_level--;
            }
            if (MONITOR_GET_OPCODE(default_memspace) == OP_RTI) {
                wait_for_return_level--;
            }
            if (wait_for_return_level < 0) {
                wait_for_return_level = 0;
            }
        }
    }

    if (wait_for_return_level == 0) {
        instruction_count--;
    }

    if (instruction_count == 0) {
        trigger_break_on_next_instruction = TRUE;
    }
}

/* called by cpu core */
void monitor_check_icount_interrupt(void)
{
    /* This is a helper for monitor_check_icount.
    It's called whenever a IRQ or NMI is executed
    and the monitor_mask[default_memspace] | MI_STEP is
    active, i.e., we're in the single step mode.   */

    if (instruction_count) {
        if (skip_jsrs == TRUE) {
            wait_for_return_level++;
        }
    }
}

int monitor_check_breakpoints(MEMSPACE mem, WORD addr)
{
    return mon_breakpoint_check_checkpoint(mem, addr, 0, e_exec); /* FIXME */
}

/* called by macro DO_INTERRUPT() in 6510(dtv)core.c */
void monitor_check_watchpoints(unsigned int lastpc, unsigned int pc)
{
    unsigned int dnr;

    if (watch_load_occurred) {
        if (watchpoints_check_loads(e_comp_space, lastpc, pc)) {
            monitor_startup(e_comp_space);
        }
        for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
            if (watchpoints_check_loads(monitor_diskspace_mem(dnr), lastpc, pc)) {
                monitor_startup(monitor_diskspace_mem(dnr));
            }
        }
        watch_load_occurred = FALSE;
    }

    if (watch_store_occurred) {
        if (watchpoints_check_stores(e_comp_space, lastpc, pc)) {
            monitor_startup(e_comp_space);
        }
        for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
            if (watchpoints_check_stores(monitor_diskspace_mem(dnr), lastpc, pc)) {
                monitor_startup(monitor_diskspace_mem(dnr));
            }
        }
        watch_store_occurred = FALSE;
    }
}

int monitor_diskspace_dnr(int mem)
{
    switch (mem) {
      case e_disk8_space:
       return 0;
      case e_disk9_space:
       return 1;
      case e_disk10_space:
       return 2;
      case e_disk11_space:
       return 3;
    }

    return -1;
}

int monitor_diskspace_mem(int dnr)
{
    switch (dnr) {
      case 0:
        return e_disk8_space;
      case 1:
        return e_disk9_space;
      case 2:
        return e_disk10_space;
      case 3:
        return e_disk11_space;
    }

    return 0;
}

void monitor_change_device(MEMSPACE mem)
{
    mon_out("Setting default device to `%s'\n",_mon_space_strings[(int) mem]);
    default_memspace = mem;
}

static void make_prompt(char *str)
{
    if (asm_mode) {
        sprintf(str, ".%04x  ", addr_location(asm_mode_addr));
    } else {
        sprintf(str, "(%s:$%04x) ",
                mon_memspace_string[default_memspace],
                addr_location(dot_addr[default_memspace]));
    }
}

void monitor_abort(void)
{
    mon_stop_output = 1;
}

static void monitor_open(void)
{
    unsigned int dnr;

    mon_console_close_on_leaving = 1;

    if (monitor_is_remote()) {
        static console_t console_log_remote = { 80, 25, 0, 0 };
        console_log = &console_log_remote;
    } else {
#if 0
        if (mon_console_close_on_leaving) {
            console_log = uimon_window_open();
            uimon_set_interface(mon_interfaces, NUM_MEMSPACES);
        } else {
            console_log = uimon_window_resume();
            mon_console_close_on_leaving = 1;
        }
#endif
        if (console_log) {
            console_log = uimon_window_resume();
        } else {
            console_log = uimon_window_open();
            uimon_set_interface(mon_interfaces, NUM_MEMSPACES);
        }
    }

    if (console_log == NULL) {
        log_error(LOG_DEFAULT, "monitor_open: could not open monitor console.");
        exit_mon = 1;
        monitor_trap_triggered = FALSE;
        return;
    }

    mon_console_close_on_leaving = console_log->console_can_stay_open ^ 1;

    if ( monitor_is_remote() ) {
        signals_pipe_set();
    }

    inside_monitor = TRUE;
    monitor_trap_triggered = FALSE;
    vsync_suspend_speed_eval();

    uimon_notify_change();

    dot_addr[e_comp_space] = new_addr(e_comp_space,
        ((WORD)((monitor_cpu_for_memspace[e_comp_space]->mon_register_get_val)(e_comp_space, e_PC))));

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        int mem = monitor_diskspace_mem(dnr);
        dot_addr[mem] = new_addr(mem,
            ((WORD)((monitor_cpu_for_memspace[mem]->mon_register_get_val)(mem, e_PC))));
    }

    if (disassemble_on_entry) {
        mon_disassemble_with_regdump(default_memspace, dot_addr[default_memspace]);
        disassemble_on_entry = 0;
    }
}

static int monitor_process(char *cmd)
{
    mon_stop_output = 0;
    if (cmd == NULL) {
        mon_out("\n");
    } else {
        if (!cmd[0]) {
            if (!asm_mode) {
                /* Repeat previous command */
                lib_free(cmd);

                cmd = last_cmd ? lib_stralloc(last_cmd) : NULL;

            } else {
                /* Leave asm mode */
            }
        }

        if (cmd) {
            if (recording) {
                if (fprintf(recording_fp, "%s\n", cmd) < 0) {
                   mon_out("Error while recording commands. "
                             "Output file closed.\n");
                   fclose(recording_fp);
                   recording_fp = NULL;
                   recording = FALSE;
                }
            }

            parse_and_execute_line(cmd);

            if (playback > 0) {
                playback_commands(playback);
            }
        }
    }
    lib_free(last_cmd);

    last_cmd = cmd;

    uimon_notify_change(); /* @SRT */

    return exit_mon;
}

void parse_and_execute_line(const char* str)
{
    char* temp_buf;
    int i, rc;

    /* duplicate the string and append two extra bytes for parsing in place */
    temp_buf = lib_malloc(strlen(str) + 3);
    strcpy(temp_buf, str);
    i = (int)strlen(str);
    temp_buf[i++] = '\n';
    temp_buf[i++] = '\0';
    temp_buf[i++] = '\0';

    prev_parse_pos = parse_pos = 0;

    if (asm_mode) {
        rc = mon_asm6502_assemble_line(temp_buf);
    } else {
        rc = mon_parse_exec_line(temp_buf);
    }

    if (rc) {
        mon_out("ERROR -- ");
        switch(rc) {
          case ERR_BAD_CMD:
            mon_out("Bad command:\n");
            break;
          case ERR_RANGE_BAD_START:
            mon_out("Bad first address in range:\n");
            break;
          case ERR_RANGE_BAD_END:
            mon_out("Bad second address in range:\n");
            break;
          case ERR_EXPECT_CHECKNUM:
            mon_out("Checkpoint number expected:\n");
            break;
          case ERR_EXPECT_END_CMD:
            mon_out("Unexpected token:\n");
            break;
          case ERR_MISSING_CLOSE_PAREN:
            mon_out("')' expected:\n");
            break;
          case ERR_INCOMPLETE_COMPARE_OP:
            mon_out("Compare operation missing an operand:\n");
            break;
          case ERR_EXPECT_FILENAME:
            mon_out("Expecting a filename:\n");
            break;
          case ERR_ADDR_TOO_BIG:
            mon_out("Address too large:\n");
            break;
          case ERR_IMM_TOO_BIG:
            mon_out("Immediate argument too large:\n");
            break;
          case ERR_EXPECT_STRING:
            mon_out("Expecting a string.\n");
            break;
          case ERR_UNDEFINED_LABEL:
            mon_out("Found an undefined label.\n");
            break;
          case ERR_EXPECT_DEVICE_NUM:
            mon_out("Expecting a device number.\n");
            break;
          case ERR_EXPECT_ADDRESS:
            mon_out("Expecting an address.\n");
            break;
          case ERR_ILLEGAL_INPUT:
          default:
            mon_out("Wrong syntax:\n");
        }
        mon_out("  %s\n", str);
        for (i = 0; i < parse_pos; i++)
            mon_out(" ");
        mon_out("  ^\n");
        asm_mode = 0;
        /*new_cmd = 1;*/
    }
    lib_free(temp_buf);
}


void mon_update_parse_pos(int add)
{
    prev_parse_pos = parse_pos;
    parse_pos += add;
}


static void monitor_close(int check)
{
    inside_monitor = FALSE;
    vsync_suspend_speed_eval();

    exit_mon--;

    if (check && exit_mon) {
        exit(0);
    }

    exit_mon = 0;

    if ( monitor_is_remote() ) {
        signals_pipe_unset();
    }

    /*
        if there is no log, or if the console can not stay open when the emulation
        runs, close the console.
    */
    if ((console_log == NULL) || (console_log->console_can_stay_open == 0)) {
        mon_console_close_on_leaving = 1;
    }

    if ( ! monitor_is_remote() ) {
        if (mon_console_close_on_leaving) {
            uimon_window_close();
        } else {
            uimon_window_suspend();
        }
    }

    if (mon_console_close_on_leaving) {
        console_log = NULL;
    }
}


void monitor_startup(MEMSPACE mem)
{
    char prompt[40];

    if (mem != e_default_space)
        default_memspace = mem;

    monitor_open();
    while (!exit_mon) {
        make_prompt(prompt);
        monitor_process(uimon_in(prompt));
    }
    monitor_close(1);
}

static void monitor_trap(WORD addr, void *unused_data)
{
    monitor_startup(e_default_space);
#ifdef HAVE_FULLSCREEN
    fullscreen_resume();
#endif

}

void monitor_startup_trap(void)
{
    if ( ! monitor_trap_triggered && ! inside_monitor ) {
        monitor_trap_triggered = TRUE;
        interrupt_maincpu_trigger_trap(monitor_trap, 0);
    }
}
