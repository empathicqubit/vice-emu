/*
 * drivetypes.h - drive-specific types like the drive context structure.
 *
 * Written by
 *  Andreas Dehmel <dehmel@forwiss.tu-muenchen.de>
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

#ifndef _DRIVETYPES_H
#define _DRIVETYPES_H

#include "cia.h"
#include "ciatimer.h"
#include "drive.h"
#include "mos6510.h"
#include "riot.h"
#include "tpi.h"
#include "types.h"
#include "via.h"

/*
 *  The philosophy behind this approach is that only the drive module knows
 *  the exact layout of the drive_context_t structure. Therefore only include
 *  drivetypes.h from source files within the drive module. All other modules
 *  only need to use pointers transparently, which only requires a forward
 *  declaration of struct drive_context_s (see below).
 */

struct drive_context_s;         /* forward declaration */
struct monitor_interface_s;
struct via_context_s;

/* This defines the memory access for the drive CPU.  */
typedef BYTE REGPARM2 drive_read_func_t(struct drive_context_s *, WORD);
typedef void REGPARM3 drive_store_func_t(struct drive_context_s *, WORD,
                                         BYTE);


/* This table is used to approximate the sync between the main and the
   drive CPU, since the two clock rates are different.  */
#define MAX_TICKS 0x1000

/*
 *  The private CPU data.
 */

typedef struct drivecpu_context_s {
    int traceflg;
    /* This is non-zero each time a Read-Modify-Write instructions that accesses
       memory is executed.  We can emulate the RMW bug of the 6502 this way.  */
    int rmw_flag; /* init to 0 */

    /* Interrupt/alarm status.  */
    struct interrupt_cpu_status_s *int_status;

    struct alarm_context_s *alarm_context;

    /* Clk guard.  */
    struct clk_guard_s *clk_guard;

    struct monitor_interface_s *monitor_interface;

    /* Value of clk for the last time mydrive_cpu_execute() was called.  */
    CLOCK last_clk;

    /* Number of cycles in excess we executed last time mydrive_cpu_execute()
       was called.  */
    CLOCK last_exc_cycles;

    CLOCK stop_clk;

    CLOCK cycle_accum;
    BYTE *d_bank_base;
    int d_bank_limit;     /* init to -1 */

    /* Information about the last executed opcode.  */
    unsigned int last_opcode_info;

    /* Public copy of the registers.  */
    mos6510_regs_t cpu_regs;

    BYTE *pageone;        /* init to NULL */

    int monspace;         /* init to e_disk[89]_space */

    char snap_module_name[12];    /* init to "DRIVECPU[01]" */

    char identification_string[8];        /* init to "DRIVE#[89]" */
} drivecpu_context_t;


/*
 *  Large data used in the CPU emulation. Often more efficient to move
 *  to the end of the drive context structure to minimize the average
 *  offset of members within the context structure.
 */

typedef struct drivecpud_context_s {

    /* Drive RAM */
    BYTE drive_ram[DRIVE_RAM_SIZE];

    /* functions */
    drive_read_func_t  *read_func[0x101];
    drive_store_func_t *store_func[0x101];
    drive_read_func_t  *read_func_watch[0x101];
    drive_store_func_t *store_func_watch[0x101];
    drive_read_func_t  *read_func_nowatch[0x101];
    drive_store_func_t *store_func_nowatch[0x101];

    unsigned long clk_conv_table[MAX_TICKS + 1];
    unsigned long clk_mod_table[MAX_TICKS + 1];

} drivecpud_context_t;


/*
 *  Some function pointers shared by several components (VIA1, CIA1581, RIOT2)
 */

typedef struct drivefunc_context_s {

    void (*iec_write)(BYTE);
    BYTE (*iec_read)(void);
    void (*parallel_set_bus)(BYTE);
    void (*parallel_set_eoi)(BYTE); /* we may be able to eleminate these... */
    void (*parallel_set_dav)(BYTE);
    void (*parallel_set_ndac)(BYTE);
    void (*parallel_set_nrfd)(BYTE);
    void (*parallel_cable_write)(BYTE, int);

} drivefunc_context_t;


/*  Additional data required for VIA1.  */
typedef struct drivevia1_context_s {
    unsigned int number;
    struct drive_s *drive_ptr;
    int parallel_id;
    int v_parieee_is_out;         /* init to 1 */
    struct iec_info_s *v_iec_info;
} drivevia1_context_t;

/*  Additional data required for VIA2.  */
typedef struct drivevia2_context_s {
    unsigned int number;
    struct drive_s *drive_ptr;
} drivevia2_context_t;

/*  Additional data required for CIA1571.  */
typedef struct drivecia1571_context_s {
    unsigned int number;
    struct drive_s *drive_ptr;
} drivecia1571_context_t;

/*  Additional data required for CIA1581.  */
typedef struct drivecia1581_context_s {
    unsigned int number;
    struct drive_s *drive_ptr;
    struct iec_info_s *iec_info;
} drivecia1581_context_t;

/*  Additional data for RIOT2.  */
typedef struct driveriot2_context_s {
    unsigned int number;
    struct drive_s *drive_ptr;
    int r_atn_active;     /* init to 0 */
    unsigned int int_num;
} driveriot2_context_t;

/*  Additional data for TPI.  */
typedef struct drivetpi_context_s {
    unsigned int number;
    struct drive_s *drive_ptr;
} drivetpi_context_t;

/*
 * The context for an entire drive.
 */

typedef struct drive_context_s {

    int mynumber;         /* init to [01] */
    CLOCK *clk_ptr;       /* shortcut to drive_clk[mynumber] */
    struct drive_s *drive_ptr;    /* shortcut to drive[mynumber] */

    drivecpu_context_t cpu;
    drivefunc_context_t func;
    via_context_t via1d1541;
    via_context_t via1d2031;
    via_context_t via2;
    cia_context_t cia1571;
    cia_context_t cia1581;
    struct iec_info_s *c_iec_info;        /* for CIA1581 */
    riot_context_t riot1;
    riot_context_t riot2;
    /*driveriot2_context_t riot2p;*/
    tpi_context_t tpid;
    drivecpud_context_t cpud;

} drive_context_t;


#endif

