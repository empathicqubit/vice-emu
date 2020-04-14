/** \file   monitor_binary.c
 *  \brief  Monitor implementation - binary network access
 *
 *  \author EmpathicQubit <empathicqubit@entan.gl>
 */

/*
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
#include <stdlib.h>
#include <string.h>

#include "ui.h"

#include "cmdline.h"
#include "lib.h"
#include "log.h"
#include "monitor.h"
#include "monitor_binary.h"
#include "montypes.h"
#include "resources.h"
#include "uiapi.h"
#include "util.h"
#include "vicesocket.h"

#include "mon_breakpoint.h"

#include "mon_register.h"

#ifdef HAVE_NETWORK

#define ADDR_LIMIT(x) ((uint16_t)(addr_mask(x)))

static vice_network_socket_t * listen_socket = NULL;
static vice_network_socket_t * connected_socket = NULL;

static char *monitor_binary_server_address = NULL;
static int monitor_binary_enabled = 0;

enum t_binary_command {
    e_MON_CMD_MEMDUMP = 0x01,
    e_MON_CMD_BANKS_GET = 0x02,

    e_MON_CMD_CHECKPOINT_GET = 0x10,
    e_MON_CMD_CHECKPOINT_SET = 0x11,
    e_MON_CMD_CHECKPOINT_DELETE = 0x12,
    e_MON_CMD_CHECKPOINT_LIST = 0x13,

    e_MON_CMD_COND_GET = 0x20,
    e_MON_CMD_COND_SET = 0x21,

    e_MON_CMD_REGISTERS_GET = 0x30,
    e_MON_CMD_REGISTERS_SET = 0x31,

    e_MON_CMD_EXIT = 0x70,
    e_MON_CMD_QUIT = 0x71,
    e_MON_CMD_ADVANCE_INSTRUCTIONS = 0x72,

    e_MON_CMD_PING = 0x80,
};
typedef enum t_binary_command BINARY_COMMAND;

enum t_binary_response {
    e_MON_RESPONSE_MEMDUMP = 0x01,

    e_MON_RESPONSE_CHECKPOINT_INFO = 0x10,
    e_MON_RESPONSE_CHECKPOINT_DELETE = 0x12,
    e_MON_RESPONSE_CHECKPOINT_LIST = 0x13,

    e_MON_RESPONSE_COND_INFO = 0x20,

    e_MON_RESPONSE_REGISTER_INFO = 0x30,

    e_MON_RESPONSE_EXIT = 0x70,
    e_MON_RESPONSE_QUIT = 0x71,
    e_MON_RESPONSE_ADVANCE_INSTRUCTIONS = 0x72,

    e_MON_RESPONSE_PING = 0x80,
    e_MON_RESPONSE_JAM = 0x81,
};
typedef enum t_binary_response BINARY_RESPONSE;

struct binary_command_s {
    uint8_t api_version;
    uint8_t length;
    uint32_t request_id;
    BINARY_COMMAND type;
    unsigned char *body;
};
typedef struct binary_command_s binary_command_t;

int monitor_binary_transmit(const char * buffer, size_t buffer_length)
{
    int error = 0;

    if (connected_socket) {
        size_t len = (size_t)vice_network_send(connected_socket, buffer, buffer_length, 0);

        if (len != buffer_length) {
            error = -1;
        } else {
            error = (int)len;
        }
    }

    return error;
}

static void monitor_binary_quit(void)
{
    vice_network_socket_close(connected_socket);
    connected_socket = NULL;
}

int monitor_binary_receive(char * buffer, size_t buffer_length)
{
    int count = 0;

    do {
        if (!connected_socket) {
            break;
        }

        count = vice_network_receive(connected_socket, buffer, buffer_length, 0);

        if (count < 0) {
            log_message(LOG_DEFAULT, "monitor_binary_receive(): vice_network_receive() returned -1, breaking connection");
            monitor_binary_quit();
        }
    } while (0);

    return count;
}

static int monitor_binary_data_available(void)
{
    int available = 0;

    if (connected_socket != NULL) {
        available = vice_network_select_poll_one(connected_socket);
    } else if (listen_socket != NULL) {
        /* we have no connection yet, allow for connection */

        if (vice_network_select_poll_one(listen_socket)) {
            connected_socket = vice_network_accept(listen_socket);
        }
    }


    return available;
}

void monitor_check_binary(void)
{
    if (monitor_binary_data_available()) {
        monitor_startup_trap();
    }
}

/*
The binary remote monitor commands are sent over a dedicated channel, specified
with the command line options -binarymonitor & -binarymonitoraddress.
The remote monitor detects a binary command because it starts with ASCII STX
(0x02). Note that there is no termination character. The command length acts as
synchronisation point.

All multibyte values are in little endian order unless otherwise specified.

Commands are structured as detailed in the COMMAND STRUCTURE section.

Responses are structured as detailed in the RESPONSE STRUCTURE section.
They can either be sent in response to a binary command, or when certain
events occur.

COMMAND STRUCTURE
==============================

byte 0: 0x02 (STX)
byte 1: API version ID (currently 0x01)
byte 2: length
    Note that the command length byte (the one after STX) does *not* count the
    STX, the command length, the command byte, or the request ID. Basically
    nothing in the header, just the body.
byte 3-6: request id
    In little endian order. All multibyte values are in little endian order,
    unless otherwise specified. There is no requirement for this to be unique,
    but it makes it easier to match up the responses if you do.
byte 7: The numeric command type. See the COMMANDS section for more details.
byte 8+: The command body. See the COMMANDS section.

RESPONSE STRUCTURE
===============================

byte 0: 0x02 (STX)
byte 1: API version ID (currently 0x01)
byte 2-5: response body length. Does not include any header fields
byte 6: response type
    This is usually the same as the command ID
byte 7: error code
    0x00: ok, everything worked
    0x80: command length is not correct for this command
    0x81: an invalid parameter occurred

See invidual command documentation for other error codes

byte 8-11: request ID
    This is the request ID given to initiate this response.
    If the value is 0xffffffff, Then the response was initiated by an event,
    such as hitting a checkpoint.
byte 12+: response body. See the COMMANDS section for more details.

COMMANDS (command body: bytes 8+, response body: bytes 12+)
======================

----------------------
0x01: MON_CMD_MEMDUMP
----------------------

Dumps a chunk of memory from a start address to an end address (inclusive).

Command body:

byte 0-1: start address
byte 2-3: end address
byte 4: memspace
    Describes which part of the computer you want to read:
    0x00: the computer (C64)
    0x01: drive 8
    0x02: drive 9
    0x03: drive 10
    0x04: drive 11
byte 5: bank ID
    Describes which bank you want. This is dependent on your
    machine. Please look at the command MON_CMD_BANKS_GET for details.

Response type:

0x01: MON_RESPONSE_MEMDUMP

Response body:

byte 0-1: The length of the memory segment.
byte 2+: The memory at the address.

----------------------
0x01: MON_CMD_BANKS_GET
----------------------

Gives a listing of all the bank IDs for the running machine.

Command body:

Currently empty.

Response type:

0x02: MON_RESPONSE_BANK_INFO

Response body:

byte 0-1: The count of the array items
byte 2: The size of each entry
byte 3+: An array with items of structure:
    byte 0: ID of the register
    byte 1-2: register value

----------------------
0x11: MON_CMD_CHECKPOINT_SET
----------------------

Sets any type of checkpoint. This combines the functionality of several
textual commands (break, watch, trace) into one, as they are all the same
with only minor variations. To set conditions, use MON_CMD_COND_SET after
executing this one.

Command body:

byte 0-1: start address
byte 2-3: end address
byte 4: stop when hit
    0x01: true
    0x00: false
byte 5: enabled
    0x01: true
    0x00: false
byte 6: CPU operation
    0x01: load
    0x02: store
    0x04: exec
byte 7: temporary
    Deletes the checkpoint after it has been hit once. This is similar to
    "until" command, but it will not resume the emulator.

Response type:

0x02: MON_RESPONSE_CHECKPOINT_INFO

Response body:

See the section CHECKPOINT RESPONSE

----------------------
0x11: MON_CMD_CHECKPOINT_LIST
----------------------

Response type:

Emits a series of MON_RESPONSE_CHECKPOINT_INFO responses
(See the section CHECKPOINT RESPONSE) followed by

0x13: MON_RESPONSE_CHECKPOINT_LIST

Response body:

MON_RESPONSE_CHECKPOINT_LIST:

byte 0-3: The total number of checkpoints

-----------------------------------
0x05: MON_CMD_COND_SET
-----------------------------------

Sets a condition on an existing checkpoint.

Command body:

byte 0-3: checkpoint number
byte 4: condition expression length
byte 5+: condition expression string
    This is the same format used on the command line. Not null terminated.

Response type:

0x04: MON_RESPONSE_COND_INFO

Response body:

Currently empty.

-----------------------------------
0x30: MON_CMD_REGISTERS_GET
-----------------------------------

Get details about the registers

Command body:

Currently empty.

Response type:

0x30: MON_RESPONSE_REGISTER_INFO

Response body:

See the section REGISTERS RESPONSE

-----------------------------------
0x31: MON_CMD_REGISTERS_SET
-----------------------------------

Set the register values

Command body:

byte 0-1: The count of the array items
byte 2: The size of each entry
byte 3+: An array with items of structure:
    byte 0: ID of the register
    byte 1-2: register value

Response type:

0x30: MON_RESPONSE_REGISTER_INFO

Response body:

See the section REGISTERS RESPONSE

-----------------------------------
0x70: MON_CMD_EXIT
-----------------------------------

Exit the monitor until the next breakpoint.

Command body:

Currently empty.

Response type:

0x70: MON_RESPONSE_EXIT

Response body:

Currently empty.

-----------------------------------
0x71: MON_CMD_QUIT
-----------------------------------

Quits VICE.

Command body:

Currently empty.

Response type:

0x71: MON_RESPONSE_QUIT

Response body:

Currently empty.

-----------------------------------
0x72: MON_CMD_ADVANCE_INSTRUCTIONS
-----------------------------------

Step over a certain number of instructions.

Command body:

byte 0: Step over subroutines?
    Should subroutines count as a single instruction?
byte 1-2: How many instructions to step over.

Response type:

0x72: MON_RESPONSE_ADVANCE_INSTRUCTIONS

Response body:

Currently empty.

-------------------
0x80: MON_CMD_PING
-------------------

Get an empty response

Command body:

Always empty

Response type:

0x80: MON_RESPONSE_PING

Response body:

Always empty

REGISTERS RESPONSE
=====================

Response type:

0x06: MON_RESPONSE_REGISTER_INFO

Response body:

byte 0-1: The count of the array items
byte 2: The size of each entry
byte 3+: An array with items of structure:
    byte 0: ID of the register
    byte 1: register size in bits
    byte 2-3: register value

CHECKPOINT RESPONSE
=====================

Response type:

0x02: MON_RESPONSE_CHECKPOINT_INFO

Response body:

byte 0-3: Checkpoint number
byte 4: Currently hit?
    0x01: true
    0x00: false

byte 5-6: start address
byte 7-8: end address
byte 9: stop when hit
    0x01: true
    0x00: false
byte 10: enabled
    0x01: true
    0x00: false
byte 11: CPU operation
    0x01: load
    0x02: store
    0x04: exec
byte 12: temporary
    Deletes the checkpoint after it has been hit once. This is similar to
    "until" command, but it will not resume the emulator.

byte 13-16: hit count
byte 17-20: ignore count
byte 21: Has condition?
    0x01: true
    0x00: false

JAM RESPONSE
===============

Response type:

0x81: MON_RESPONSE_JAM

Response body:

Currently empty.

*/

#define ASC_STX 0x02

#define MON_BINARY_API_VERSION 0x01

#define MON_EVENT_ID 0xffffffff

#define MON_ERR_OK            0
#define MON_ERR_CMD_INVALID_LENGTH 0x80  /* command length is not correct */
#define MON_ERR_INVALID_PARAMETER 0x81  /* command has invalid parameters */

static void uint32_to_little_endian(uint32_t input, unsigned char *output) {
    output[0] = input & 0xFFu;
    output[1] = (input >> 8) & 0xFFu;
    output[2] = (input >> 16) & 0xFFu;
    output[3] = (uint8_t)(input >> 24) & 0xFFu;
}

static uint32_t little_endian_to_uint32(unsigned char *input) {
    return (input[3] << 24) + (input[2] << 16) + (input[1] << 8) + input[0];
}

static uint16_t little_endian_to_uint16(unsigned char *input) {
    return (input[1] << 8) + input[0];
}

static void uint16_to_little_endian(uint16_t input, unsigned char *output) {
    output[0] = input & 0xFFu;
    output[1] = (input >> 8) & 0xFFu;
}

static void monitor_binary_response(uint32_t length, uint8_t response_type, uint8_t errorcode, uint32_t request_id, unsigned char * body)
{
    unsigned char response[12];

    response[0] = ASC_STX;
    response[1] = MON_BINARY_API_VERSION;
    uint32_to_little_endian(length, &response[2]);
    response[6] = response_type;
    response[7] = errorcode;
    uint32_to_little_endian(request_id, &response[8]);

    monitor_binary_transmit((char*)response, sizeof response);

    if (body != NULL) {
        monitor_binary_transmit((char*)body, length);
    }
}

static void monitor_binary_response_register_info(uint32_t request_id) {
    unsigned char *response;
    uint16_t count;
    uint32_t response_size = 2;
    uint8_t item_size = 3;
    mon_reg_list_t *regs = mon_register_list_get(e_comp_space);
    mon_reg_list_t *regs_cursor = regs;
    unsigned char *response_cursor;

    do {
        ++regs_cursor;
    } while(regs_cursor->name);

    count = (regs_cursor - regs) / sizeof(mon_reg_list_t);

    response_size += count * item_size;
    response = lib_malloc(response_size);
    response_cursor = response;

    regs_cursor = regs;

    uint16_to_little_endian(count, response_cursor);
    response_cursor += 2;

    *response_cursor = item_size;
    ++response_cursor;
    do {
        *response_cursor = regs_cursor->id;
        ++response_cursor;

        *response_cursor = regs_cursor->size;
        ++response_cursor;

        uint16_to_little_endian((uint16_t)regs_cursor->val, response_cursor);
        response_cursor += 2;

        ++regs_cursor;
    } while(regs_cursor->name);

    monitor_binary_response(response_size, e_MON_RESPONSE_REGISTER_INFO, MON_ERR_OK, request_id, response);

    lib_free(response);
}

void monitor_binary_response_checkpoint_info(uint32_t request_id, mon_checkpoint_t *checkpt, bool hit) {
    unsigned char response[22];
    MEMORY_OP op = (MEMORY_OP)(
        (checkpt->check_store ? e_store : 0) 
        | (checkpt->check_load ? e_load : 0) 
        | (checkpt->check_exec ? e_exec : 0)
    );

    uint32_to_little_endian(checkpt->checknum, &response[0]);
    response[4] = hit;

    uint16_to_little_endian((uint16_t)addr_location(checkpt->start_addr), &response[5]);
    uint16_to_little_endian((uint16_t)addr_location(checkpt->end_addr), &response[7]);
    response[9] = checkpt->stop;
    response[10] = checkpt->enabled;
    response[11] = op;
    response[12] = checkpt->temporary;

    uint32_to_little_endian((uint32_t)checkpt->hit_count, &response[13]);
    uint32_to_little_endian((uint32_t)checkpt->ignore_count, &response[17]);
    response[21] = !!checkpt->condition;

    monitor_binary_response(sizeof (response), e_MON_RESPONSE_CHECKPOINT_INFO, MON_ERR_OK, request_id, response);
}

static void monitor_binary_error(uint8_t errorcode, uint32_t request_id)
{
    monitor_binary_response(0, 0, errorcode, request_id, NULL);
}

static int monitor_binary_process_ping(binary_command_t *command) {
    monitor_binary_response(0, e_MON_RESPONSE_PING, MON_ERR_OK, command->request_id, NULL);

    return 1;
}

static int monitor_binary_process_checkpoint_list(binary_command_t *command) {
    unsigned char response[sizeof(uint32_t)];
    unsigned int i, len;
    uint32_t request_id = command->request_id;
    mon_checkpoint_t **checkpts = mon_breakpoint_checkpoint_list_get(&len);

    for(i = 0; i < len; i++) {
        monitor_binary_response_checkpoint_info(request_id, checkpts[i], 0);
    }

    uint32_to_little_endian((uint32_t)len, &response[0]);

    monitor_binary_response(sizeof(uint32_t), e_MON_RESPONSE_CHECKPOINT_LIST, MON_ERR_OK, request_id, response);

    lib_free(checkpts);

    return 1;
}

static int monitor_binary_process_checkpoint_set(binary_command_t *command) {
    int brknum;
    mon_checkpoint_t *checkpt;
    unsigned char *body = command->body;

    if (command->length < 8) {
        monitor_binary_error(MON_ERR_CMD_INVALID_LENGTH, command->request_id);
        return 1;
    }

    brknum = mon_breakpoint_add_checkpoint(
        (MON_ADDR)little_endian_to_uint16(&body[0]),
        (MON_ADDR)little_endian_to_uint16(&body[2]),
        (bool)body[4],
        (MEMORY_OP)body[6],
        (bool)body[7]
        );

    if (!body[5]) {
        mon_breakpoint_switch_checkpoint(e_OFF, brknum);
    }

    checkpt = mon_breakpoint_find_checkpoint(brknum);

    monitor_binary_response_checkpoint_info(command->request_id, checkpt, 0);

    return 1;
}

static int monitor_binary_process_advance_instructions(binary_command_t *command) {
    uint8_t step_over_subroutines = command->body[0];
    uint16_t count = little_endian_to_uint16(&command->body[1]);

    if (command->length < 3) {
        monitor_binary_error(MON_ERR_CMD_INVALID_LENGTH, command->request_id);
        return 1;
    }

    if (step_over_subroutines) {
        mon_instructions_next(count);
    } else {
        mon_instructions_step(count);
    }

    monitor_binary_response(0, e_MON_RESPONSE_ADVANCE_INSTRUCTIONS, MON_ERR_OK, command->request_id, NULL);

    return 0;
}

static int monitor_binary_process_registers_get(binary_command_t *command) {
    monitor_binary_response_register_info(command->request_id);

    return 1;
}

static int monitor_binary_process_exit(binary_command_t *command) {
    monitor_binary_response(0, e_MON_RESPONSE_EXIT, MON_ERR_OK, command->request_id, NULL);

    return 0;
}

static int monitor_binary_process_quit(binary_command_t *command) {
    mon_quit();

    monitor_binary_response(0, e_MON_RESPONSE_QUIT, MON_ERR_OK, command->request_id, NULL);

    return 0;
}

static int monitor_binary_process_memdump(binary_command_t *command) {
    unsigned int i;
    unsigned char *response;
    unsigned char *response_cursor;

    uint32_t response_size = 2;
    int banknum = 0;
    MEMSPACE memspace = e_default_space;

    unsigned char *body = command->body;

    uint16_t startaddress = little_endian_to_uint16(&body[0]);
    uint16_t endaddress = little_endian_to_uint16(&body[2]);

    uint8_t requested_memspace = body[4];
    uint8_t requested_banknum = body[5];

    uint16_t length = endaddress - startaddress + 1;

    if(command->length < 6) {
        monitor_binary_error(MON_ERR_CMD_INVALID_LENGTH, command->request_id);
        return 1;
    }

    // TODO: Other systems?
    if (requested_memspace == 0) {
        memspace = e_comp_space;
    } else if (requested_memspace == 1) {
        memspace = e_disk8_space;
    } else if (requested_memspace == 2) {
        memspace = e_disk9_space;
    } else if (requested_memspace == 3) {
        memspace = e_disk10_space;
    } else if (requested_memspace == 4) {
        memspace = e_disk11_space;
    } else {
        monitor_binary_error(MON_ERR_INVALID_PARAMETER, command->request_id);
        log_message(LOG_DEFAULT, "monitor binary memdump: Unknown memspace %u", requested_memspace);
        return 1;
    }

    if (!mon_banknum_validate(memspace, requested_banknum)) {
        monitor_binary_error(MON_ERR_INVALID_PARAMETER, command->request_id);
        log_message(LOG_DEFAULT, "monitor binary memdump: Unknown bank %u", requested_banknum);
        return 1;
    }

    banknum = requested_banknum;

    if (startaddress > endaddress) {
        monitor_binary_error(MON_ERR_INVALID_PARAMETER, command->request_id);
        log_message(LOG_DEFAULT, "monitor binary memdump: wrong start and/or end address %04x - %04x",
                    startaddress, endaddress);
        return 1;
    }

    response_size += length;

    response = lib_malloc(response_size);
    response_cursor = response;

    uint16_to_little_endian(length, response_cursor);
    response_cursor += 2;

    for (i = 0; i < length; i++) {
        *response_cursor = mon_get_mem_val_ex(memspace, banknum, (uint16_t)ADDR_LIMIT(startaddress + i));
        ++response_cursor;
    }

    monitor_binary_response(response_size, e_MON_RESPONSE_MEMDUMP, MON_ERR_OK, command->request_id, response);

    lib_free(response);

    return 1;
}

static int monitor_binary_process_command(unsigned char * pbuffer, int buffer_size, int * pbuffer_pos) {
    binary_command_t *command = lib_malloc(sizeof(binary_command_t));
    BINARY_COMMAND command_type;
    int min_length;
    int cont;

    command->api_version = (uint8_t)pbuffer[1];

    if (command->api_version != 0x01) {
        monitor_binary_error(MON_ERR_INVALID_PARAMETER, command->request_id);
        return;
    }

    command->length = (uint8_t)pbuffer[2];

    if (command->api_version >= 0x01) {
        command->request_id = little_endian_to_uint32(&pbuffer[3]);
        command->type = pbuffer[7];
        command->body = &pbuffer[8];
    }

    command_type = command->type;
    if (command_type == e_MON_CMD_PING) {
        cont = monitor_binary_process_ping(command);
    } else if(command_type == e_MON_CMD_MEMDUMP) {
        cont = monitor_binary_process_memdump(command);
    } else if(command_type == e_MON_CMD_CHECKPOINT_SET) {
        cont = monitor_binary_process_checkpoint_set(command);
    } else if(command_type == e_MON_CMD_CHECKPOINT_LIST) {
        cont = monitor_binary_process_checkpoint_list(command);
    } else if(command_type == e_MON_CMD_REGISTERS_GET) {
        cont = monitor_binary_process_registers_get(command);
    } else if(command_type == e_MON_CMD_EXIT) {
        cont = monitor_binary_process_exit(command);
    } else if(command_type == e_MON_CMD_QUIT) {
        cont = monitor_binary_process_quit(command);
    } else if(command_type == e_MON_CMD_ADVANCE_INSTRUCTIONS) {
        cont = monitor_binary_process_advance_instructions(command);
    } else {
        log_message(LOG_DEFAULT,
                "monitor_network binary command: unknown command %d, "
                "skipping command length of %u",
                command, command->length);
    }

    *pbuffer_pos = 0;
    pbuffer[0] = 0;

    lib_free(command);

    return cont;
}

static int monitor_binary_activate(void)
{
    vice_network_socket_address_t * server_addr = NULL;
    int error = 1;

    do {
        if (!monitor_binary_server_address) {
            break;
        }

        server_addr = vice_network_address_generate(monitor_binary_server_address, 0);
        if (!server_addr) {
            break;
        }

        listen_socket = vice_network_server(server_addr);
        if (!listen_socket) {
            break;
        }

        error = 0;
    } while (0);

    if (server_addr) {
        vice_network_address_close(server_addr);
    }

    return error;
}

int monitor_binary_get_command_line(void)
{
    static char buffer[300] = { 0 };
    static int bufferpos = 0;

    while(monitor_binary_data_available()) {
        /* Do not read more from network until all commands in current buffer is fully processed */
        int body_length;
        uint8_t api_version;
        int header_size = 8;

        int n = monitor_binary_receive(buffer, 1);
        if (n == 0) {
            monitor_binary_quit();
            return 0;
        } else if (n < 0) {
            monitor_binary_quit();
            return 0;
        }
        
        if (buffer[0] != ASC_STX) {
            continue;
        }

        n = monitor_binary_receive(&buffer[1], 2);

        if (n < 2) {
            monitor_binary_quit();
            return 0;
        }

        api_version = buffer[1];
        body_length = buffer[2];

        if (api_version == 0x01) {
            header_size = 8;
        } else {
            continue;
        }

        n = monitor_binary_receive(&buffer[3], header_size - 3 + body_length);

        if (n < header_size - 3 + body_length) {
            monitor_binary_quit();
            return 0;
        }

        ui_dispatch_events();

        if(!monitor_binary_process_command((unsigned char*)buffer, sizeof buffer, &bufferpos)) {
            return 0;
        }
    }

    ui_dispatch_events();

    return 1;
}

static int monitor_binary_deactivate(void)
{
    if (listen_socket) {
        vice_network_socket_close(listen_socket);
        listen_socket = NULL;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */

/*! \internal \brief set the binary monitor to the enabled or disabled state

 \param val
   if 0, disable the network monitor; else, enable it.

 \param param
   unused

 \return
   0 on success. else -1.
*/
static int set_binary_monitor_enabled(int value, void *param)
{
    int val = value ? 1 : 0;

    if (!val) {
        if (monitor_binary_enabled) {
            if (monitor_binary_deactivate() < 0) {
                return -1;
            }
        }
        monitor_binary_enabled = 0;
        return 0;
    } else {
        if (!monitor_binary_enabled) {
            if (monitor_binary_activate() < 0) {
                return -1;
            }
        }

        monitor_binary_enabled = 1;
        return 0;
    }
}

/*! \internal \brief set the network address of the network monitor

 \param name
   pointer to a buffer which holds the network server addresss.

 \param param
   unused

 \return
   0 on success, else -1.
*/
static int set_binary_server_address(const char *name, void *param)
{
    if (monitor_binary_server_address != NULL && name != NULL
        && strcmp(name, monitor_binary_server_address) == 0) {
        return 0;
    }

    if (monitor_binary_enabled) {
        monitor_binary_deactivate();
    }
    util_string_set(&monitor_binary_server_address, name);

    if (monitor_binary_enabled) {
        monitor_binary_activate();
    }

    return 0;
}

/*! \brief string resources used by the binary monitor module */
static const resource_string_t resources_string[] = {
    { "BinaryMonitorServerAddress", "ip4://127.0.0.1:29172", RES_EVENT_NO, NULL,
      &monitor_binary_server_address, set_binary_server_address, NULL },
    RESOURCE_STRING_LIST_END
};

/*! \brief integer resources used by the binary monitor module */
static const resource_int_t resources_int[] = {
    { "BinaryMonitorServer", 0, RES_EVENT_STRICT, (resource_value_t)0,
      &monitor_binary_enabled, set_binary_monitor_enabled, NULL },
    RESOURCE_INT_LIST_END
};

/*! \brief initialize the binary monitor resources
 \return
   0 on success, else -1.

 \remark
   Registers the string and the integer resources
*/
int monitor_binary_resources_init(void)
{
    if (resources_register_string(resources_string) < 0) {
        return -1;
    }

    return resources_register_int(resources_int);
}

/*! \brief uninitialize the network monitor resources */
void monitor_binary_resources_shutdown(void)
{
    monitor_binary_deactivate();
    monitor_binary_quit();

    lib_free(monitor_binary_server_address);
}

/* ------------------------------------------------------------------------- */

static const cmdline_option_t cmdline_options[] =
{
    { "-binarymonitor", SET_RESOURCE, CMDLINE_ATTRIB_NONE,
      NULL, NULL, "BinaryMonitorServer", (resource_value_t)1,
      NULL, "Enable binary monitor" },
    { "+binarymonitor", SET_RESOURCE, CMDLINE_ATTRIB_NONE,
      NULL, NULL, "BinaryMonitorServer", (resource_value_t)0,
      NULL, "Disable binary monitor" },
    { "-binarymonitoraddress", SET_RESOURCE, CMDLINE_ATTRIB_NEED_ARGS,
      NULL, NULL, "BinaryMonitorServerAddress", NULL,
      "<Name>", "The local address the binary monitor should bind to" },
    CMDLINE_LIST_END
};

/*! \brief initialize the command-line options'
 \return
   0 on success, else -1.

 \remark
   Registers the command-line options
*/
int monitor_binary_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}

int monitor_is_binary(void)
{
    return connected_socket != NULL;
}

ui_jam_action_t monitor_binary_ui_jam_dialog(const char *format, ...)
{
    monitor_binary_response(0, e_MON_RESPONSE_JAM, MON_ERR_OK, MON_EVENT_ID, NULL);

    return UI_JAM_MONITOR;
}

#else

int monitor_binary_resources_init(void)
{
    return 0;
}

void monitor_binary_resources_shutdown(void)
{
}

int monitor_binary_cmdline_options_init(void)
{
    return 0;
}

void monitor_check_binary(void)
{
}

int monitor_binary_transmit(const char * buffer, size_t buffer_length)
{
    return 0;
}

char * monitor_binary_get_command_line(void)
{
    return 0;
}

int monitor_is_remote(void)
{
    return 0;
}

ui_jam_action_t monitor_network_ui_jam_dialog(const char *format, ...)
{
    return UI_JAM_HARD_RESET;
}

#endif
