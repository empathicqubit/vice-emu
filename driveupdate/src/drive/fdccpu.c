/*
 * drivecpu.c - 6502 processor emulation of CBM disk drives.
 *
 * Written by
 *  Ettore Perazzoli <ettore@comm2000.it>
 *  Andreas Boose <viceteam@t-online.de>
 *
 * Patches by
 *  Andre Fachat <a.fachat@physik.tu-chemnitz.de>
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

#include "6510core.h"
#include "alarm.h"
#include "clkguard.h"
#include "debug.h"
#include "drive.h"
#include "fdccpu.h"
#include "drive-check.h"
#include "drivemem.h"
#include "drivetypes.h"
#include "interrupt.h"
#include "lib.h"
#include "log.h"
#include "machine-drive.h"
#include "machine.h"
#include "mem.h"
#include "monitor.h"
#include "mos6510.h"
#include "snapshot.h"
#include "types.h"
#include "fdd.h"


#define DRIVE_CPU

static void drive_jam(drive_context_t *drv);

static BYTE drive_bank_read(int bank, WORD addr, void *context);
static BYTE drive_bank_peek(int bank, WORD addr, void *context);
static void drive_bank_store(int bank, WORD addr, BYTE value, void *context);
static void fdccpu_toggle_watchpoints(int flag, void *context);
static void fdccpu_set_bank_base(void *context);

static interrupt_cpu_status_t *fdccpu_int_status_ptr[DRIVE_NUM];


monitor_interface_t *fdccpu_monitor_interface_get(unsigned int dnr)
{
    return drive_context[dnr]->fdccpu->monitor_interface;
}

void fdccpu_setup_context(struct drive_context_s *drv)
{
    monitor_interface_t *mi;
    fdccpu_context_t *cpu;

    drv->fdccpu = lib_calloc(1, sizeof(fdccpu_context_t));
    cpu = drv->fdccpu;

    drv->fdccpud = lib_calloc(1, sizeof(fdccpud_context_t));

    cpu->int_status = interrupt_cpu_status_new();
    interrupt_cpu_status_init(cpu->int_status, &(cpu->last_opcode_info));
    fdccpu_int_status_ptr[drv->mynumber] = cpu->int_status;

    cpu->rmw_flag = 0;
    cpu->d_bank_limit = -1;
    cpu->pageone = NULL;
    cpu->snap_module_name = lib_msprintf("FDCCPU%d", drv->mynumber);
    cpu->identification_string = lib_msprintf("FDRIVE#%d", drv->mynumber + 8);
    cpu->monitor_interface = monitor_interface_new();
    mi = cpu->monitor_interface;
    mi->context = (void *)drv;
    mi->cpu_regs = &(cpu->cpu_regs);
    mi->z80_cpu_regs = NULL;
    mi->int_status = cpu->int_status;
    mi->clk = &(drive_fdcclk[drv->mynumber]);
    mi->current_bank = 0;
    mi->mem_bank_list = NULL;
    mi->mem_bank_from_name = NULL;
    mi->get_line_cycle = NULL;
    mi->mem_bank_read = drive_bank_read;
    mi->mem_bank_peek = drive_bank_peek;
    mi->mem_bank_write = drive_bank_store;
    mi->mem_ioreg_list_get = drivefdcmem_ioreg_list_get;
    mi->toggle_watchpoints_func = fdccpu_toggle_watchpoints;
    mi->set_bank_base = fdccpu_set_bank_base;
    cpu->monspace = monitor_diskspace_mem(drv->mynumber) + DRIVE_NUM;
}

/* ------------------------------------------------------------------------- */

#define LOAD(a)           (drv->fdccpud->read_func[(a) >> 8](drv, (WORD)(a)))
#define LOAD_ZERO(a)      (drv->fdccpud->read_func[0](drv, (WORD)(a)))
#define LOAD_ADDR(a)      (LOAD(a) | (LOAD((a) + 1) << 8))
#define LOAD_ZERO_ADDR(a) (LOAD_ZERO(a) | (LOAD_ZERO((a) + 1) << 8))
#define STORE(a, b)       (drv->fdccpud->store_func[(a) >> 8](drv, (WORD)(a), \
                          (BYTE)(b)))
#define STORE_ZERO(a, b)  (drv->fdccpud->store_func[0](drv, (WORD)(a), \
                          (BYTE)(b)))

/* FIXME: pc can not jump to VIA adress space in 1541 and 1571 emulation.  */
/* FIXME: SFD1001 does not use bank_base at all due to messy memory mapping.
   We should use tables like in maincpu instead (AF) */
#define JUMP(addr)                                       \
    do {                                                 \
        reg_pc = (addr);                                 \
        if (reg_pc >= 0xfc00) {                          \
            cpu->d_bank_base = drv->drive->fdcrom - 0xfc00; \
            cpu->d_bank_limit = 0xfffd;                  \
        } else {                                         \
            cpu->d_bank_base = NULL;                     \
            cpu->d_bank_limit = -1;                      \
        }                                                \
    } while (0)

/* ------------------------------------------------------------------------- */

/* This is the external interface for banked memory access.  */

static BYTE drive_bank_read(int bank, WORD addr, void *context)
{
    drive_context_t *drv = (drive_context_t *)context;

    return drv->fdccpud->read_func[addr >> 8](drv, addr);
}

/* FIXME: use peek in IO area */
static BYTE drive_bank_peek(int bank, WORD addr, void *context)
{
    drive_context_t *drv = (drive_context_t *)context;

    return drv->fdccpud->read_func[addr >> 8](drv, addr);
}

static void drive_bank_store(int bank, WORD addr, BYTE value, void *context)
{
    drive_context_t *drv = (drive_context_t *)context;

    drv->fdccpud->store_func[addr >> 8](drv, addr, value);
}

/* ------------------------------------------------------------------------- */

static void cpu_reset(drive_context_t *drv)
{
    int preserve_monitor;

    preserve_monitor = drv->fdccpu->int_status->global_pending_int & IK_MONITOR;

    log_message(drv->drive->log, "RESET.");

    interrupt_cpu_status_reset(drv->fdccpu->int_status);

    *(drv->fdcclk_ptr) = 6;

    if (preserve_monitor)
        interrupt_monitor_trap_on(drv->fdccpu->int_status);
}

static void fdccpu_toggle_watchpoints(int flag, void *context)
{
    drive_context_t *drv = (drive_context_t *)context;

    if (flag) {
        memcpy(drv->fdccpud->read_func, drv->fdccpud->read_func_watch,
               sizeof(drive_read_func_t *) * 0x101);
        memcpy(drv->fdccpud->store_func, drv->fdccpud->store_func_watch,
               sizeof(drive_store_func_t *) * 0x101);
    } else {
        memcpy(drv->fdccpud->read_func, drv->fdccpud->read_func_nowatch,
               sizeof(drive_read_func_t *) * 0x101);
        memcpy(drv->fdccpud->store_func, drv->fdccpud->store_func_nowatch,
               sizeof(drive_store_func_t *) * 0x101);
    }
}

void fdccpu_reset_clk(drive_context_t *drv)
{
    drv->fdccpu->last_clk = *(drv->clk_ptr);
    drv->fdccpu->last_exc_cycles = 0;
    drv->fdccpu->stop_clk = 0;
}

void fdccpu_reset(drive_context_t *drv)
{
    int preserve_monitor;

    *(drv->fdcclk_ptr) = 0;
    fdccpu_reset_clk(drv);

    preserve_monitor = drv->fdccpu->int_status->global_pending_int & IK_MONITOR;

    interrupt_cpu_status_reset(drv->fdccpu->int_status);

    if (preserve_monitor)
        interrupt_monitor_trap_on(drv->fdccpu->int_status);

    /* FIXME -- ugly, should be changed in interrupt.h */
    interrupt_trigger_reset(drv->fdccpu->int_status, *(drv->fdcclk_ptr));
}

void fdccpu_trigger_reset(unsigned int dnr)
{
    interrupt_trigger_reset(fdccpu_int_status_ptr[dnr], drive_fdcclk[dnr] + 1);
}

static void fdc_cpu_early_init(drive_context_t *drv)
{
    drv->fdccpu->clk_guard = clk_guard_new(drv->fdcclk_ptr, CLOCK_MAX
                                        - CLKGUARD_SUB_MIN);

    drv->fdccpu->alarm_context = alarm_context_new(
                                  drv->fdccpu->identification_string);
}

void fdccpu_early_init_all(void)
{
    unsigned int dnr;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++)
        fdc_cpu_early_init(drive_context[dnr]);
}

void fdccpu_shutdown(drive_context_t *drv)
{
    fdccpu_context_t *cpu;

    cpu = drv->fdccpu;

    if (cpu->alarm_context != NULL)
        alarm_context_destroy(cpu->alarm_context);
    if (cpu->clk_guard != NULL)
        clk_guard_destroy(cpu->clk_guard);

    monitor_interface_destroy(cpu->monitor_interface);
    interrupt_cpu_status_destroy(cpu->int_status);

    lib_free(cpu->snap_module_name);
    lib_free(cpu->identification_string);
    lib_free(drv->fdccpud);
    lib_free(cpu);
}

void fdccpu_init(drive_context_t *drv, int type)
{
    drivemem_init(drv, type);
    fdccpu_reset(drv);
}

inline void fdccpu_wake_up(drive_context_t *drv)
{
    /* FIXME: this value could break some programs, or be way too high for
       others.  Maybe we should put it into a user-definable resource.  */
    if (*(drv->clk_ptr) - drv->fdccpu->last_clk > 0xffffff
        && *(drv->fdcclk_ptr) > 934639) {
        log_message(drv->drive->log, "FDC Skipping cycles.");
        drv->fdccpu->last_clk = *(drv->clk_ptr);
    }
}

inline void fdccpu_sleep(drive_context_t *drv)
{
    /* Currently does nothing.  But we might need this hook some day.  */
}

/* Make sure the drive clock counters never overflow; return nonzero if
   they have been decremented to prevent overflow.  */
static CLOCK fdccpu_prevent_clk_overflow(drive_context_t *drv, CLOCK sub)
{
    if (sub != 0) {
        /* First, get in sync with what the main CPU has done.  Notice that
           `clk' has already been decremented at this point.  */
        if (drv->drive->enable) {
            if (drv->fdccpu->last_clk < sub) {
                /* Hm, this is kludgy.  :-(  */
                fdccpu_execute_all(*(drv->clk_ptr) + sub);
            }
            drv->fdccpu->last_clk -= sub;
        } else {
            drv->fdccpu->last_clk = *(drv->clk_ptr);
        }
    }

    /* Then, check our own clock counters.  */
    return clk_guard_prevent_overflow(drv->fdccpu->clk_guard);
}

void fdccpu_prevent_clk_overflow_all(CLOCK sub)
{
    unsigned int dnr;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++)
        fdccpu_prevent_clk_overflow(drive_context[dnr], sub);
}

/* Handle a ROM trap. */
inline static DWORD drive_trap_handler(drive_context_t *drv)
{
    return (DWORD)-1;
}

static void drive_generic_dma(void)
{
    /* Generic DMA hosts can be implemented here.
       Not very likey for disk drives. */
}

/* -------------------------------------------------------------------------- */

/* Return nonzero if a pending NMI should be dispatched now.  This takes
   account for the internal delays of the 6510, but does not actually check
   the status of the NMI line.  */
inline static int interrupt_check_nmi_delay(interrupt_cpu_status_t *cs,
                                            CLOCK cpu_clk)
{
    CLOCK nmi_clk = cs->nmi_clk + INTERRUPT_DELAY;

    /* Branch instructions delay IRQs and NMI by one cycle if branch
       is taken with no page boundary crossing.  */
    if (OPINFO_DELAYS_INTERRUPT(*cs->last_opcode_info_ptr))
        nmi_clk++;

    if (cpu_clk >= nmi_clk)
        return 1;

    return 0;
}

/* Return nonzero if a pending IRQ should be dispatched now.  This takes
   account for the internal delays of the 6510, but does not actually check
   the status of the IRQ line.  */
inline static int interrupt_check_irq_delay(interrupt_cpu_status_t *cs,
                                            CLOCK cpu_clk)
{
    CLOCK irq_clk = cs->irq_clk + INTERRUPT_DELAY;

    /* Branch instructions delay IRQs and NMI by one cycle if branch
       is taken with no page boundary crossing.  */
    if (OPINFO_DELAYS_INTERRUPT(*cs->last_opcode_info_ptr))
        irq_clk++;

    /* If an opcode changes the I flag from 1 to 0, the 6510 needs
       one more opcode before it triggers the IRQ routine.  */
    if (cpu_clk >= irq_clk) {
        if (!OPINFO_ENABLES_IRQ(*cs->last_opcode_info_ptr)) {
            return 1;
        } else {
            cs->global_pending_int |= IK_IRQPEND;
        }
    }
    return 0;
}

/* MPi: For some reason MSVC is generating a compiler fatal error when optimising this function? */
#ifdef _MSC_VER
#pragma optimize("",off)
#endif
/* -------------------------------------------------------------------------- */
/* Execute up to the current main CPU clock value.  This automatically
   calculates the corresponding number of clock ticks in the drive.  */
void fdccpu_execute(drive_context_t *drv, CLOCK clk_value)
{
    CLOCK cycles;
    fdccpu_context_t *cpu;

#define reg_a   (cpu->cpu_regs.a)
#define reg_x   (cpu->cpu_regs.x)
#define reg_y   (cpu->cpu_regs.y)
#define reg_pc  (cpu->cpu_regs.pc)
#define reg_sp  (cpu->cpu_regs.sp)
#define reg_p   (cpu->cpu_regs.p)
#define flag_z  (cpu->cpu_regs.z)
#define flag_n  (cpu->cpu_regs.n)

    cpu = drv->fdccpu;

    fdccpu_wake_up(drv);

    /* Calculate number of main CPU clocks to emulate */
    if (clk_value > cpu->last_clk)
        cycles = clk_value - cpu->last_clk;
    else
        cycles = 0;

    cpu->stop_clk += cycles;

    /* Run drive CPU emulation until the stop_clk clock has been reached.
     * There appears to be a nasty 32-bit overflow problem here, so we
     * paper over it by only considering subtractions of 2nd complement
     * integers. */
    while ((int) (*(drv->fdcclk_ptr) - cpu->stop_clk) < 0) {

/* Include the 6502/6510 CPU emulation core.  */

#define CLK (*(drv->fdcclk_ptr))
#define RMW_FLAG (cpu->rmw_flag)
#define PAGE_ONE (cpu->pageone)
#define LAST_OPCODE_INFO (cpu->last_opcode_info)
#define LAST_OPCODE_ADDR (cpu->last_opcode_addr)
#define TRACEFLG (debug.fdccpu_traceflg[drv->mynumber])

#define CPU_INT_STATUS (cpu->int_status)

#define ALARM_CONTEXT (cpu->alarm_context)

#define JAM() drive_jam(drv)

#define ROM_TRAP_ALLOWED() 1

#define ROM_TRAP_HANDLER() drive_trap_handler(drv)

#define CALLER (cpu->monspace)

#define DMA_FUNC drive_generic_dma()

#define DMA_ON_RESET

#define drivecpu_byte_ready_egde_clear() fdd_byte_ready_edge_fdc(drv->drive->fdds[0])
#define drivecpu_byte_ready() fdd_byte_ready_edge_fdc(drv->drive->fdds[0])

#define cpu_reset() (cpu_reset)(drv)
#define bank_limit (cpu->d_bank_limit)
#define bank_base (cpu->d_bank_base)

#include "6510core.c"

    }

    cpu->last_clk = clk_value;
    fdccpu_sleep(drv);
}

#ifdef _MSC_VER
#pragma optimize("",on)
#endif

void fdccpu_execute_all(CLOCK clk_value)
{
    unsigned int dnr;

    for (dnr = 0; dnr < DRIVE_NUM; dnr++) {
        if (drive_context[dnr]->drive->enable)
            fdccpu_execute(drive_context[dnr], clk_value);
    }
}

/* ------------------------------------------------------------------------- */

static void fdccpu_set_bank_base(void *context)
{
    drive_context_t *drv;
    fdccpu_context_t *cpu;

    drv = (drive_context_t *)context;
    cpu = drv->fdccpu;

    JUMP(reg_pc);
}

/* Inlining this fuction makes no sense and would only bloat the code.  */
static void drive_jam(drive_context_t *drv)
{
    unsigned int tmp;
    char *dname = "  Drive";
    fdccpu_context_t *cpu;

    cpu = drv->fdccpu;

    switch(drv->drive->type) {
      case DRIVE_TYPE_1001:
        dname = " F1001";
        break;
      case DRIVE_TYPE_2040:
        dname = " F2040";
        break;
      case DRIVE_TYPE_3040:
        dname = " F3040";
        break;
      case DRIVE_TYPE_4040:
        dname = " F4040";
        break;
      case DRIVE_TYPE_8050:
        dname = " F8050";
        break;
      case DRIVE_TYPE_8250:
        dname = " F8250";
      break;
    }

    tmp = machine_jam("%s CPU: JAM at $%04X  ", dname, (int)reg_pc);
    switch (tmp) {
      case JAM_RESET:
        reg_pc = 0xeaa0;
        fdccpu_set_bank_base((void *)drv);
        machine_trigger_reset(MACHINE_RESET_MODE_SOFT);
        break;
      case JAM_HARD_RESET:
        reg_pc = 0xeaa0;
        fdccpu_set_bank_base((void *)drv);
        machine_trigger_reset(MACHINE_RESET_MODE_HARD);
        break;
      case JAM_MONITOR:
        caller_space = drv->fdccpu->monspace;
        monitor_startup();
        break;
      default:
        CLK++;
    }
}

/* ------------------------------------------------------------------------- */

#define SNAP_MAJOR 1
#define SNAP_MINOR 1

int fdccpu_snapshot_write_module(drive_context_t *drv, snapshot_t *s)
{
    snapshot_module_t *m;
    fdccpu_context_t *cpu;

    cpu = drv->fdccpu;

    m = snapshot_module_create(s, drv->fdccpu->snap_module_name,
                               ((BYTE)(SNAP_MAJOR)), ((BYTE)(SNAP_MINOR)));
    if (m == NULL)
        return -1;

    if (0
        || SMW_DW(m, (DWORD) *(drv->fdcclk_ptr)) < 0
        || SMW_B(m, (BYTE)MOS6510_REGS_GET_A(&(cpu->cpu_regs))) < 0
        || SMW_B(m, (BYTE)MOS6510_REGS_GET_X(&(cpu->cpu_regs))) < 0
        || SMW_B(m, (BYTE)MOS6510_REGS_GET_Y(&(cpu->cpu_regs))) < 0
        || SMW_B(m, (BYTE)MOS6510_REGS_GET_SP(&(cpu->cpu_regs))) < 0
        || SMW_W(m, (WORD)MOS6510_REGS_GET_PC(&(cpu->cpu_regs))) < 0
        || SMW_B(m, (BYTE)MOS6510_REGS_GET_STATUS(&(cpu->cpu_regs))) < 0
        || SMW_DW(m, (DWORD)(cpu->last_opcode_info)) < 0
        || SMW_DW(m, (DWORD)(cpu->last_clk)) < 0
        || SMW_DW(m, (DWORD)(cpu->cycle_accum)) < 0
        || SMW_DW(m, (DWORD)(cpu->last_exc_cycles)) < 0
        || SMW_DW(m, (DWORD)(cpu->stop_clk)) < 0
        )
        goto fail;

    if (interrupt_write_snapshot(cpu->int_status, m) < 0)
        goto fail;

    if (drive_check_old(drv->drive->type)) {
        if (SMW_BA(m, drv->fdccpud->drive_ram, 0x100) < 0)
            goto fail;
    }

    if (interrupt_write_new_snapshot(cpu->int_status, m) < 0)
        goto fail;

    return snapshot_module_close(m);

fail:
    if (m != NULL)
        snapshot_module_close(m);
    return -1;
}

int fdccpu_snapshot_read_module(drive_context_t *drv, snapshot_t *s)
{
    BYTE major, minor;
    snapshot_module_t *m;
    BYTE a, x, y, sp, status;
    WORD pc;
    fdccpu_context_t *cpu;

    cpu = drv->fdccpu;

    m = snapshot_module_open(s, drv->fdccpu->snap_module_name, &major, &minor);
    if (m == NULL)
        return -1;

    /* Before we start make sure all devices are reset.  */
    fdccpu_reset(drv);

    /* XXX: Assumes `CLOCK' is the same size as a `DWORD'.  */
    if (0
        || SMR_DW(m, drv->fdcclk_ptr) < 0
        || SMR_B(m, &a) < 0
        || SMR_B(m, &x) < 0
        || SMR_B(m, &y) < 0
        || SMR_B(m, &sp) < 0
        || SMR_W(m, &pc) < 0
        || SMR_B(m, &status) < 0
        || SMR_DW_UINT(m, &(cpu->last_opcode_info)) < 0
        || SMR_DW(m, &(cpu->last_clk)) < 0
        || SMR_DW(m, &(cpu->cycle_accum)) < 0
        || SMR_DW(m, &(cpu->last_exc_cycles)) < 0
        || SMR_DW(m, &(cpu->stop_clk)) < 0
        )
        goto fail;

    MOS6510_REGS_SET_A(&(cpu->cpu_regs), a);
    MOS6510_REGS_SET_X(&(cpu->cpu_regs), x);
    MOS6510_REGS_SET_Y(&(cpu->cpu_regs), y);
    MOS6510_REGS_SET_SP(&(cpu->cpu_regs), sp);
    MOS6510_REGS_SET_PC(&(cpu->cpu_regs), pc);
    MOS6510_REGS_SET_STATUS(&(cpu->cpu_regs), status);

    log_message(drv->drive->log, "RESET (For undump).");

    interrupt_cpu_status_reset(cpu->int_status);

    machine_drive_reset(drv);

    if (interrupt_read_snapshot(cpu->int_status, m) < 0)
        goto fail;

    if (drive_check_old(drv->drive->type)) {
        if (SMR_BA(m, drv->fdccpud->drive_ram, 0x100) < 0)
            goto fail;
    }

    /* Update `*bank_base'.  */
    JUMP(reg_pc);

    if (interrupt_read_new_snapshot(drv->fdccpu->int_status, m) < 0) {
        goto fail;
    }

    return snapshot_module_close(m);

fail:
    if (m != NULL)
        snapshot_module_close(m);
    return -1;
}

