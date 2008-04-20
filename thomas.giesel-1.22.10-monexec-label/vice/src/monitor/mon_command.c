/*
 * mon_command.c - The VICE built-in monitor command table.
 *
 * Written by
 *  Daniel Sladic <sladic@eecg.toronto.edu>
 *  Ettore Perazzoli <ettore@comm2000.it>
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

#include "vice.h"

#include <stdio.h>
#include <string.h>

#include "mon_command.h"
#include "montypes.h"
#include "mon_parse.h" /* FIXME ! */
#include "mon_util.h"
#include "uimon.h"
#include "util.h"


typedef struct mon_cmds_s {
   const char *str;
   const char *abbrev;
   const char *param_names;
   const char *description;
} mon_cmds_t;

static const mon_cmds_t mon_cmd_array[] = {
   { "~",               "",
     "<number>",
     "Display the specified number in decimal, hex, octal and binary." },

   { ">",               "",
     "[<address>] <data_list>",
     "Write the specified data at `address'." },

   { "@",               "",
     "<disk command>",
     "Perform a disk command on the currently attached disk image on drive 8.\n"
     "The specified disk command is sent to the drive's channel #15." },

/*
   { "]",               "",
     NULL,
     "*** unimplemented ***" },
*/

   { "a",               "",
     "<address> [ <instruction> [: <instruction>]* ]",
     "Assemble instructions to the specified address.  If only one\n"
     "instruction is specified, enter assembly mode (enter an empty line to\n"
     "exit assembly mode)." },

   { "add_label",       "al",
     "[<memspace>] <address> <label>",
     "<memspace> is one of: C: 8: 9: 10: 11:\n"
     "<address>  is the address which should get the label.\n"
     "<label>    is the name of the label; it must start with a dot (\".\").\n\n"
     "Map a given address to a label.  This label can be used when entering\n"
     "assembly code and is shown during disassembly.  Additionally, it can\n"
     "be used whenever an address must be specified." },

   { "bank",            "",
     "[<memspace>] [bankname]",
     "If bankname is not given, print the possible banks for the memspace.\n"
     "If bankname is given set the current bank in the memspace to the given\n"
     "bank." },

   { "bload",           "bl",
     "\"<filename>\" <device> <address>",
     "Load the specified file into memory at the specified address.\n"
     "If device is 0, the file is read from the file system." },

   { "block_read",      "br",
     "<track> <sector> [<address>]",
     "Read the block at the specified track and sector.  If an address is\n"
     "specified, the data is loaded into memory.  If no address is given, the\n"
     "data is displayed using the default datatype." },

   { "break",           "",
     "[<address> [if <cond_expr>] ]",
     "If no address is given, the currently valid watchpoints are printed.\n"
     "If an address is given, a breakpoint is set for that address and the\n"
     "breakpoint number is printed.  A conditional expression can also be\n"
     "specified for the breakpoint.  For more information on conditions, see\n"
     "the CONDITION command." },

/*
   { "brmon",           "",
     NULL,
     "*** unimplemented ***" },
*/

   { "bsave",           "bs",
     "\"<filename>\" <device> <address1> <address2>",
     "Save the memory from address1 to address2 to the specified file.\n"
     "If device is 0, the file is written to the file system." },

   { "block_write",     "bw",
     "<track> <sector> <address>",
     "Write a block of data at `address' on the specified track and sector\n"
     "of disk in drive 8." },

   { "cd",              "",
     "<directory>",
     "Change the working directory." },

   { "command",         "",
     "<checknum> \"<command>\"",
     "Specify `command' as the command to execute when checkpoint `checknum'\n"
     "is hit.  Note that the `x' command is not yet supported as a\n"
     "command argument." },


   { "compare",         "c",
     "<address_range> <address>",
     "Compare memory from the source specified by the address range to the\n"
     "destination specified by the address.  The regions may overlap.  Any\n"
     "values that miscompare are displayed using the default displaytype." },

   { "condition",       "cond",
     "<checknum> if <cond_expr>",
     "Each time the specified checkpoint is examined, the condition is\n"
     "evaluated.  If it evalutes to true, the checkpoint is activated.\n"
     "Otherwise, it is ignored.  If registers are specified in the expression,\n"
     "the values used are those at the time the checkpoint is examined, not\n"
     "when the condition is set.\n"
     "The condition can make use of registers (.A, .X, .Y, .PC, .SP) and\n"
     "compare them (==, !=, <, >, <=, >=) again other registers or constants.\n"
     "Registers can be the registers of other devices; this is denoted by\n"
     "a memspace prefix (i.e., c:, 8:, 9:, 10:, 11:\n"
     "Examples: .A == 0, .X == .Y, 8:.X == .X\n" },

   { "cpu",             "",
     "<type>",
     "Specify the type of CPU currently used (6502/z80)." },

   { "disass",          "d",
     "[<address> [<address>]]",
     "Disassemble instructions.  If two addresses are specified, they are\n"
     "used as a start and end address.  If only one is specified, it is\n"
     "treated as the start address and a default number of instructions are\n"
     "disassembled.  If no addresses are specified, a default number of\n"
     "instructions are disassembled from the dot address." },

   { "delete",          "del",
     "<checknum>",
     "Delete checkpoint `checknum'." },

   { "delete_label",    "dl",
     "[<memspace>] <label>",
     "<memspace> is one of: C: 8: 9: 10: 11:\n"
     "<label>    is the name of the label; it must start with a dot (\".\").\n\n"
     "Delete a previously defined label." },

   { "device",          "dev",
     "[c:|8:|9:|10:|11:]",
     "Set the default memory device to either the computer `c:' or the\n"
     "specified disk drive (`8:', `9:')." },

   { "disable",         "",
     "<checknum>",
     "Disable checkpoint `checknum'." },

/*
   { "down",            "",
     NULL,
     "*** unimplemented ***" },
*/

   { "dump",            "",
     "\"<filename>\"",
     "Write a snapshot of the machine into the file specified.\n"
     "This snapshot is compatible with a snapshot written out by the UI.\n"
     "Note: No ROM images are included into the dump." },

   { "enable",          "",
     "<checknum>",
     "Enable checkpoint `checknum'." },

   { "exit",            "x",
     NULL,
     "Leave the monitor and return to execution." },

   { "fill",            "f",
     "<address_range> <data_list>",
     "Fill memory in the specified address range with the data in\n"
     "<data_list>.  If the size of the address range is greater than the size\n"
     "of the data_list, the data_list is repeated." },

   { "goto",            "g",
     "<address>",
     "Change the PC to ADDRESS and continue execution" },

   { "help",            "?",
     "[<command>]",
     "If no argument is given, prints out a list of all available commands\n" 
     "If an argument is given, prints out specific help for that command." },

   { "hunt",            "h",
     "<address_range> <data_list>",
     "Hunt memory in the specified address range for the data in\n"
     "<data_list>.  If the data is found, the starting address of the match\n"
     "is displayed.  The entire range is searched for all possible matches." },

   { "i",               "",
     "<address_opt_range>",
     "Display memory contents as PETSCII text." },

   { "ii",              "",
     "<address_opt_range>",
     "Display memory contents as screen code text." },

   { "ignore",          "",
     "<checknum> [<count>]",
     "Ignore a checkpoint a given number of crossings.  If no count is given,\n"
     "the default value is 1." },

   { "io",              "",
     NULL,
     "Print out the I/O area of the emulated machine." },

   { "keybuf",          "",
     "\"<string>\"",
     "Put the specified string into the keyboard buffer." },

   { "load",            "l",
     "\"<filename>\" <device> [<address>]",
     "Load the specified file into memory at the specified address. Set BASIC\n"
     "pointers appropriately if loaded into computer memory (not all emulators).\n"
     "Use (otherwise ignored) two-byte load address from file if no address\n"
     "specified.\n"
     "If device is 0, the file is read from the file system." },

   { "load_labels",     "ll",
     "[<memspace>] \"<filename>\"",
     "Load a file containing a mapping of labels to addresses.  If no memory\n"
     "space is specified, the default readspace is used.\n\n" 
     "The format of the file is the one written out by the `save_labels' command;\n" 
     "it consists of some `add_label' commands, written one after the other." },

   { "mem",             "m",
     "[<data_type>] [<address_opt_range>]",
     "Display the contents of memory.  If no datatype is given, the default\n"
     "is used.  If only one address is specified, the length of data\n"
     "displayed is based on the datatype.  If no addresses are given, the\n"
     "'dot' address is used." },

   { "memchar",         "mc",
     "[<data_type>] [<address_opt_range>]",
     "Display the contents of memory as character data.  If only one address\n"
     "is specified, only one character is displayed.  If no addresses are\n"
     "given, the ``dot'' address is used." },

   { "move",            "t",
     "<address_range> <address>",
     "Move memory from the source specified by the address range to\n"
     "the destination specified by the address.  The regions may overlap." },

   { "memsprite",       "ms",
     "[<data_type>] [<address_opt_range>]",
     "Display the contents of memory as sprite data.  If only one address is\n"
     "specified, only one sprite is displayed.  If no addresses are given,\n"
     "the ``dot'' address is used." },

   { "next",            "n",
     NULL,
     "Advance to the next instruction.  Subroutines are treated as\n"
     "a single instruction." },

   { "playback",        "pb",
     "\"<filename>\"",
     "Monitor commands from the specified file are read and executed.  This\n"
     "command stops at the end of file or when a STOP command is read." },

   { "print",           "p",
     "<expression>",
     "Evaluate the specified expression and output the result." },

   { "quit",            "",
     NULL,
#ifdef OS2
     "Leave the monitor and return to execution." },
#else
     "Exit the emulator immediately."},
#endif

   { "radix",           "rad",
     "[H|D|O|B]",
     "Set the default radix to hex, decimal, octal, or binary.  With no\n"
     "argument, the current radix is printed." },

   { "record",          "rec",
     "\"<filename>\"",
     "After this command, all commands entered are written to the specified\n"
     "file until the STOP command is entered." },

   { "registers",       "r",
     "[<reg_name> = <number> [, <reg_name> = <number>]*]",
     "Assign respective registers.  With no parameters, display register\n"
     "values." },

   { "return",          "ret",
     NULL,
     "Continues execution and returns to the monitor just before the next\n"
     "RTS or RTI is executed." },

   { "save",            "s",
     "\"<filename>\" <device> <address1> <address2>",
     "Save the memory from address1 to address2 to the specified file.\n"
     "Write two-byte load address.\n"
     "If device is 0, the file is written to the file system." },

   { "save_labels",     "sl",
     "[<memspace>] \"<filename>\"",
     "Save labels to a file.  If no memory space is specified, all of the\n"
     "labels are saved." },

   { "screen",         "sc",
     NULL,
     "Displays the contents of the screen." },

   { "show_labels",     "shl",
     "[<memspace>]",
     "Display current label mappings.  If no memory space is specified, show\n"
     "all labels." },

   { "sidefx",          "sfx",
     "[on|off|toggle]",
     "Control how monitor generated reads affect memory locations that have\n"
     "read side-effects.  If the argument is 'on' then reads may cause\n"
     "side-effects.  If the argument is 'off' then reads don't cause\n"
     "side-effects.  If the argument is 'toggle' then the current mode is\n"
     "switched.  No argument displays the current state." },

   { "step",            "z",
     "[<count>]",
     "Single-step through instructions.  COUNT allows stepping\n"
     "more than a single instruction at a time." },

   { "stop",            "",
     NULL,
     "Stop recording commands.  See `record'." },

/*
   { "system",          "sys",
     NULL,
     "*** unimplemented ***" },
*/

   { "trace",           "tr",
     "[address [address]]",
     "Set a tracepoint.  If a single address is specified, set a tracepoint\n"
     "for that address.  If two addresses are specified, set a tracepoint\n"
     "for the memory locations between the two addresses." },

   { "until",           "un",
     "[<address>]",
     "If no address is given, the currently valid breakpoints are printed.\n"
     "If an address is given, a temporary breakpoint is set for that address\n"
     "and the breakpoint number is printed.  Control is returned to the\n"
    "emulator by this command.  The breakpoint is deleted once it is hit." },

   { "undump",          "",
     "\"<filename>\"",
     "Read a snapshot of the machine from the file specified." },

/*
   { "up",              "",
     NULL,
     "*** unimplemented ***" },
*/

/*
   { "verify",          "v",
     NULL,
     "*** unimplemented ***" },
*/

   { "watch",           "w",
     "[loadstore] [address [address]]",
     "Set a watchpoint.  If a single address is specified, set a watchpoint\n"
     "for that address.  If two addresses are specified, set a watchpoint\n"
     "for the memory locations between the two addresses.\n"
     "`loadstore' is either `load' or `store' to specify on which operation\n"
     "the monitor breaks. If not specified, the monitor breaks on both\n"
     "operations." },

   { NULL }

};

static int mon_command_lookup_index(const char *str)
{
    int num = 0;

    if (str == NULL)
        return -1;

    do {
        if ((strcasecmp(str, mon_cmd_array[num].str) == 0) ||
            (strcasecmp(str, mon_cmd_array[num].abbrev) == 0)) {
           return num;
        }
        num++;
    } while (mon_cmd_array[num].str != NULL);

    return -1;
}

void mon_command_print_help(const char *cmd)
{
    if (cmd == NULL) {
        const mon_cmds_t *c;
        int column = 0;

        /* Print on two columns.  This could be a lot nicer, but I am lazy.  */
        mon_out("\nAvailable commands are:\n\n");
        for (c = mon_cmd_array; c->str != NULL; c++) {
            int tot = 0;

            tot += strlen(c->str);
            if (tot == 0)        /* "Empty" command?  */
                continue;
            mon_out("%s", c->str);

            if (!util_check_null_string(c->abbrev)) {
                mon_out(" (%s)", c->abbrev);
                tot += 3 + strlen(c->abbrev);
            }

            if (tot > 40 || column == 1) {
                mon_out("\n");
                column = 0;
            } else {
                for (; tot < 40; tot++)
                    mon_out(" ");
                column = 1;
            }
            if (mon_stop_output != 0) break;
        }
        mon_out("\n\n");
    } else {
        int cmd_num;

        cmd_num = mon_command_lookup_index(cmd);

        if (cmd_num == -1)
            mon_out("Command `%s' unknown.\n", cmd);
        else if (mon_cmd_array[cmd_num].description == NULL)
            mon_out("No help available for `%s'\n", cmd);
        else {
            const mon_cmds_t *c;

            c = &mon_cmd_array[cmd_num];

            mon_out("\nSyntax: %s %s\n",
                      c->str,
                      c->param_names != NULL ? c->param_names : "");
            if (!util_check_null_string(c->abbrev))
                mon_out("Abbreviation: %s\n", c->abbrev);
            mon_out("\n%s\n\n", c->description);
        }
    }
}

