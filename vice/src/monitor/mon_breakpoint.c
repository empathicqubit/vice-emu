/*
 * mon_breakpoint.c - The VICE built-in monitor breakpoint functions.
 *
 * Written by
 *  Andreas Boose <viceteam@t-online.de>
 *  Daniel Sladic <sladic@eecg.toronto.edu>
 *  Ettore Perazzoli <ettore@comm2000.it>
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

#include "interrupt.h"
#include "lib.h"
#include "log.h"
#include "mon_breakpoint.h"
#include "mon_disassemble.h"
#include "mon_util.h"
#include "montypes.h"
#include "uimon.h"


#define any_breakpoints(mem) (breakpoints[(mem)] != NULL)

struct checkpoint_s {
    int checknum;
    MON_ADDR start_addr;
    MON_ADDR end_addr;
    int hit_count;
    int ignore_count;
    cond_node_t *condition;
    char *command;
    bool trace;
    bool enabled;
    bool watch_load;
    bool watch_store;
    bool temporary;
};
typedef struct checkpoint_s checkpoint_t;

struct checkpoint_list_s {
   checkpoint_t *checkpt;
   struct checkpoint_list_s *next;
};
typedef struct checkpoint_list_s checkpoint_list_t;

static int breakpoint_count;
checkpoint_list_t *breakpoints[NUM_MEMSPACES];

void mon_breakpoint_init(void)
{
    breakpoint_count = 1;
}

static void remove_checkpoint_from_list(checkpoint_list_t **head, checkpoint_t *cp)
{
    checkpoint_list_t *cur_entry, *prev_entry;

    cur_entry = *head;
    prev_entry = NULL;

    while (cur_entry) {
        if (cur_entry->checkpt == cp)
            break;

        prev_entry = cur_entry;
        cur_entry = cur_entry->next;
    }

    if (!cur_entry) {
        log_error(LOG_ERR, "Invalid checkpoint entry!");
        return;
    } else {
        if (!prev_entry) {
            *head = cur_entry->next;
        } else {
             prev_entry->next = cur_entry->next;
        }
        lib_free(cur_entry);
    }
}

static checkpoint_t *find_checkpoint(int brknum)
{
    checkpoint_list_t *ptr;
    int i;

    for (i = FIRST_SPACE; i <= LAST_SPACE; i++) {
        ptr = breakpoints[i];
        while (ptr) {
            if (ptr->checkpt->checknum == brknum)
                return ptr->checkpt;
            ptr = ptr->next;
        }

        ptr = watchpoints_load[i];
        while (ptr) {
            if (ptr->checkpt->checknum == brknum)
                return ptr->checkpt;
            ptr = ptr->next;
        }

        ptr = watchpoints_store[i];
        while (ptr) {
            if (ptr->checkpt->checknum == brknum)
                return ptr->checkpt;
            ptr = ptr->next;
        }
    }

    return NULL;
}

void mon_breakpoint_switch_checkpoint(int op, int cp_num)
{
    checkpoint_t *cp;
    cp = find_checkpoint(cp_num);

    if (!cp) {
        mon_out("#%d not a valid checkpoint\n", cp_num);
    } else {
        cp->enabled = op;
        mon_out("Set checkpoint #%d to state: %s\n",
                cp_num, (op == e_ON) ? "enabled" : "disabled");
    }
}

void mon_breakpoint_set_ignore_count(int cp_num, int count)
{
    checkpoint_t *cp;
    cp = find_checkpoint(cp_num);

    if (!cp) {
        mon_out("#%d not a valid checkpoint\n", cp_num);
    } else {
        cp->ignore_count = count;
        mon_out("Ignoring the next %d crossings of checkpoint #%d\n",
                  count, cp_num);
    }
}

static void print_checkpoint_info(checkpoint_t *cp)
{
    if (cp->trace) {
        mon_out("TRACE: ");
    } else if (cp->watch_load || cp->watch_store) {
        mon_out("WATCH: ");
    } else {
        if (cp->temporary)
            mon_out("UNTIL: ");
        else
            mon_out("BREAK: ");
    }
    mon_out("%d %s:$%04x",cp->checknum,
        mon_memspace_string[addr_memspace(cp->start_addr)],addr_location(cp->start_addr));
    if (mon_is_valid_addr(cp->end_addr) && (cp->start_addr != cp->end_addr))
        mon_out("-$%04x",addr_location(cp->end_addr));

    if (cp->watch_load)
        mon_out(" load");
    if (cp->watch_store)
        mon_out(" store");

    mon_out("   %s\n", (cp->enabled==e_ON) ? "enabled" : "disabled");

    if (cp->condition) {
        mon_out("\tCondition: ");
        mon_print_conditional(cp->condition);
        mon_out("\n");
    }
    if (cp->command)
        mon_out("\tCommand: %s\n", cp->command);
}

void mon_breakpoint_print_checkpoints(void)
{
    int i, any_set = 0;
    checkpoint_t *bp;

    for (i = 1; i < breakpoint_count; i++) {
        if ((bp = find_checkpoint(i))) {
            print_checkpoint_info(bp);
            any_set = 1;
        }
    }

    if (!any_set)
        mon_out("No breakpoints are set\n");
}

void mon_breakpoint_delete_checkpoint(int cp_num)
{
    int i;
    checkpoint_t *cp = NULL;
    MEMSPACE mem;

    if (cp_num == -1) {
        /* Add user confirmation here. */
        mon_out("Deleting all checkpoints\n");
        for (i = 1; i < breakpoint_count; i++) {
            cp = find_checkpoint(i);
            if (cp)
                mon_breakpoint_delete_checkpoint(i);
        }
    }
    else if (!(cp = find_checkpoint(cp_num))) {
        mon_out("#%d not a valid checkpoint\n", cp_num);
        return;
    } else {
        mem = addr_memspace(cp->start_addr);

        if (!(cp->watch_load) && !(cp->watch_store)) {
            remove_checkpoint_from_list(&(breakpoints[mem]), cp);

            if (!any_breakpoints(mem)) {
                monitor_mask[mem] &= ~MI_BREAK;
                if (!monitor_mask[mem])
                    interrupt_monitor_trap_off(mon_interfaces[mem]->int_status);
            }
        } else {
            if (cp->watch_load)
                remove_checkpoint_from_list(&(watchpoints_load[mem]), cp);
            if (cp->watch_store)
                remove_checkpoint_from_list(&(watchpoints_store[mem]), cp);

            if (!any_watchpoints(mem)) {
                monitor_mask[mem] &= ~MI_WATCH;
                mon_interfaces[mem]->toggle_watchpoints_func(0,
                    mon_interfaces[mem]->context);

                if (!monitor_mask[mem])
                    interrupt_monitor_trap_off(mon_interfaces[mem]->int_status);
            }
        }
    }
    if (cp != NULL) {
        mon_delete_conditional(cp->condition);
        lib_free(cp->command);
        cp->command = NULL;
    }
}

void mon_breakpoint_set_checkpoint_condition(int cp_num,
                                             cond_node_t *cnode)
{
    checkpoint_t *cp;
    cp = find_checkpoint(cp_num);

    if (!cp) {
        mon_out("#%d not a valid checkpoint\n", cp_num);
    } else {
        cp->condition = cnode;

        mon_out("Setting checkpoint %d condition to: ", cp_num);
        mon_print_conditional(cnode);
        mon_out("\n");
    }
}


void mon_breakpoint_set_checkpoint_command(int cp_num, char *cmd)
{
    checkpoint_t *bp;
    bp = find_checkpoint(cp_num);

    if (!bp) {
        mon_out("#%d not a valid checkpoint\n", cp_num);
    } else {
        bp->command = cmd;
        mon_out("Setting checkpoint %d command to: %s\n",
                  cp_num, cmd);
    }
}

static checkpoint_list_t *search_checkpoint_list(checkpoint_list_t *head, unsigned loc)
{
    checkpoint_list_t *cur_entry;

    cur_entry = head;

    /* The list should be sorted in increasing order. If the current entry
       is > than the search item, we can drop out early.
    */
    while (cur_entry) {
        if (mon_is_in_range(cur_entry->checkpt->start_addr,
            cur_entry->checkpt->end_addr, loc))
            return cur_entry;

        cur_entry = cur_entry->next;
    }

    return NULL;
}

static int compare_checkpoints(checkpoint_t *bp1, checkpoint_t *bp2)
{
    unsigned addr1, addr2;
    /* Returns < 0 if bp1 < bp2
               = 0 if bp1 = bp2
               > 0 if bp1 > bp2
    */

    addr1 = addr_location(bp1->start_addr);
    addr2 = addr_location(bp2->end_addr);

    if (addr1 < addr2)
        return -1;

    if (addr1 > addr2)
        return 1;

    return 0;
}

bool monitor_breakpoint_check_checkpoint(MEMSPACE mem, WORD addr,
                                         checkpoint_list_t *list)
{
    checkpoint_list_t *ptr;
    checkpoint_t *cp;
    bool result = FALSE;
    MON_ADDR temp;
    const char *type;

    ptr = search_checkpoint_list(list, addr);

    while (ptr && mon_is_in_range(ptr->checkpt->start_addr,
           ptr->checkpt->end_addr, addr)) {
        cp = ptr->checkpt;
        ptr = ptr->next;
        if (cp && cp->enabled == e_ON) {
            /* If condition test fails, skip this checkpoint */
            if (cp->condition) {
                if (!mon_evaluate_conditional(cp->condition)) {
                    continue;
                }
            }

            /* Check if the user specified some ignores */
            if (cp->ignore_count) {
                cp->ignore_count--;
                continue;
            }

            cp->hit_count++;

            result = TRUE;

            temp = new_addr(mem,
                            (monitor_cpu_for_memspace[mem]->mon_register_get_val)(mem, e_PC));
            if (cp->trace) {
                type = "Trace";
                result = FALSE;
            }
            else if (cp->watch_load)
                type = "Watch-load";
            else if (cp->watch_store)
                type = "Watch-store";
            else
                type = "Break";

            /*archdep_open_monitor_console(&mon_input, &mon_output);*/
            mon_out("#%d (%s) ", cp->checknum, type);
            mon_disassemble_instr(temp);

            if (cp->command) {
                mon_out("Executing: %s\n", cp->command);
                parse_and_execute_line(cp->command);
            }

            if (cp->temporary)
                mon_breakpoint_delete_checkpoint(cp->checknum);
        }
    }
    return result;
}

static void add_to_checkpoint_list(checkpoint_list_t **head, checkpoint_t *cp)
{
    checkpoint_list_t *new_entry, *cur_entry, *prev_entry;

    new_entry = lib_malloc(sizeof(checkpoint_list_t));
    new_entry->checkpt = cp;

    cur_entry = *head;
    prev_entry = NULL;

    /* Make sure the list is in increasing order. (Ranges are entered
       based on the lower bound) This way if the searched for address is
       less than the current ptr, we can skip the rest of the list. Note
       that ranges that wrap around 0xffff aren't handled in this scheme.
       Suggestion: Split the range and create two entries.
    */
    while (cur_entry && (compare_checkpoints(cur_entry->checkpt, cp) <= 0) ) {
        prev_entry = cur_entry;
        cur_entry = cur_entry->next;
    }

    if (!prev_entry) {
        *head = new_entry;
        new_entry->next = cur_entry;
        return;
    }

    prev_entry->next = new_entry;
    new_entry->next = cur_entry;
}

static 
int breakpoint_add_checkpoint(MON_ADDR start_addr, MON_ADDR end_addr,
                                  bool is_trace, bool is_load, bool is_store,
                                  bool is_temp, bool do_print)
{
    checkpoint_t *new_cp;
    MEMSPACE mem;
    long len;

    len = mon_evaluate_address_range(&start_addr, &end_addr, FALSE, 0);
    new_cp = lib_malloc(sizeof(checkpoint_t));

    new_cp->checknum = breakpoint_count++;
    new_cp->start_addr = start_addr;
    new_cp->end_addr = end_addr;
    new_cp->trace = is_trace;
    new_cp->enabled = e_ON;
    new_cp->hit_count = 0;
    new_cp->ignore_count = 0;
    new_cp->condition = NULL;
    new_cp->command = NULL;
    new_cp->watch_load = is_load;
    new_cp->watch_store = is_store;
    new_cp->temporary = is_temp;

    mem = addr_memspace(start_addr);
    if (!is_load && !is_store) {
        if (!any_breakpoints(mem)) {
            monitor_mask[mem] |= MI_BREAK;
            interrupt_monitor_trap_on(mon_interfaces[mem]->int_status);
        }

        add_to_checkpoint_list(&(breakpoints[mem]), new_cp);
    } else {
        if (!any_watchpoints(mem)) {
            monitor_mask[mem] |= MI_WATCH;
            mon_interfaces[mem]->toggle_watchpoints_func(1,
                mon_interfaces[mem]->context);
            interrupt_monitor_trap_on(mon_interfaces[mem]->int_status);
        }

        if (is_load)
            add_to_checkpoint_list(&(watchpoints_load[mem]), new_cp);
        if (is_store)
            add_to_checkpoint_list(&(watchpoints_store[mem]), new_cp);
    }

    if (is_temp)
        exit_mon = 1;

    if (do_print)
        print_checkpoint_info(new_cp);

    return new_cp->checknum;
}

int mon_breakpoint_add_checkpoint(MON_ADDR start_addr, MON_ADDR end_addr,
                                  bool is_trace, bool is_load, bool is_store,
                                  bool is_temp)
{
    return breakpoint_add_checkpoint(start_addr, end_addr,
                                  is_trace, is_load, is_store,
                                  is_temp, TRUE );
}

mon_breakpoint_type_t mon_breakpoint_is(MON_ADDR address)
{
    MEMSPACE mem = addr_memspace(address);
    WORD addr = addr_location(address);
    checkpoint_list_t *ptr;

    ptr = search_checkpoint_list(breakpoints[mem], addr);
    
    if (!ptr)
        return BP_NONE;

    return (ptr->checkpt->enabled == e_ON) ? BP_ACTIVE : BP_INACTIVE;
}

void mon_breakpoint_set(MON_ADDR address)
{
    MEMSPACE mem = addr_memspace(address);
    WORD addr = addr_location(address);
    checkpoint_list_t *ptr;

    ptr = search_checkpoint_list(breakpoints[mem], addr);
    
    if (ptr) {
        /* there's a breakpoint, so enable it */
        ptr->checkpt->enabled = e_ON;
    } else {
        /* there's no breakpoint, so set a new one */
        breakpoint_add_checkpoint(address, address,
                                  FALSE, FALSE, FALSE, FALSE, FALSE );
    }
}

void mon_breakpoint_unset(MON_ADDR address)
{
    MEMSPACE mem = addr_memspace(address);
    WORD addr = addr_location(address);
    checkpoint_list_t *ptr;

    ptr = search_checkpoint_list(breakpoints[mem], addr);
    
    if (ptr) {
        /* there's a breakpoint, so remove it */
        remove_checkpoint_from_list( &breakpoints[mem], ptr->checkpt );
    }
}

void mon_breakpoint_enable(MON_ADDR address)
{
    MEMSPACE mem = addr_memspace(address);
    WORD addr = addr_location(address);
    checkpoint_list_t *ptr;

    ptr = search_checkpoint_list(breakpoints[mem], addr);
    
    if (ptr) {
        /* there's a breakpoint, so enable it */
        ptr->checkpt->enabled = e_ON;
    }
}

void mon_breakpoint_disable(MON_ADDR address)
{
    MEMSPACE mem = addr_memspace(address);
    WORD addr = addr_location(address);
    checkpoint_list_t *ptr;

    ptr = search_checkpoint_list(breakpoints[mem], addr);
    
    if (ptr) {
        /* there's a breakpoint, so disable it */
        ptr->checkpt->enabled = e_OFF;
    }
}

