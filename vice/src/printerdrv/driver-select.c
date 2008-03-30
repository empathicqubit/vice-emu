/*
 * driver-select.c - Select a printer driver.
 *
 * Written by
 *  Andreas Boose <boose@linux.rz.fh-hannover.de>
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

#include "cmdline.h"
#include "driver-select.h"
#include "drv-ascii.h"
#include "resources.h"
#include "types.h"
#include "utils.h"


struct driver_select_list_s {
    driver_select_t driver_select;
    struct driver_select_list_s *next;
};
typedef struct driver_select_list_s driver_select_list_t;


/* Names of currently used printer driver.  To be removed.  */
static char *printer_driver[] = { NULL, NULL, NULL };

/* Currently used printer driver.  */
static driver_select_t driver_select[3];

/* Pointer to registered printer driver.  */
static driver_select_list_t *driver_select_list = NULL;


static int set_printer_driver(resource_value_t v, void *param)
{
    const char *name = (const char *)v;
    driver_select_list_t *list;

    list = driver_select_list;

    if (list == NULL)
        return -1;

    do {
        if (!strcmp(list->driver_select.drv_name, name)) {
            util_string_set(&printer_driver[(int)param], name);
            memcpy(&driver_select[(int)param], &(list->driver_select),
                   sizeof(driver_select_t));
            return 0;
        }
        list = list->next;
    } while (list != NULL);

    return -1;
}

static resource_t resources[] = {
    {"Printer4Driver", RES_STRING, (resource_value_t)"ascii",
      (resource_value_t *)&printer_driver[0], set_printer_driver, (void *)0 },
    {"Printer5Driver", RES_STRING, (resource_value_t)"ascii",
      (resource_value_t *)&printer_driver[1], set_printer_driver, (void *)1 },
    {"PrinterUserportDriver", RES_STRING, (resource_value_t)"ascii",
      (resource_value_t *)&printer_driver[2], set_printer_driver, (void *)2 },
    {NULL}
};

int driver_select_init_resources(void)
{
    return resources_register(resources);
}

static cmdline_option_t cmdline_options[] =
{
    { "-pr4drv", SET_RESOURCE, 1, NULL, NULL, "Printer4Driver", NULL,
     "<name>", "Specify name of printer driver for device #4" },
    { "-pr5drv", SET_RESOURCE, 1, NULL, NULL, "Printer5Driver", NULL,
     "<name>", "Specify name of printer driver for device #5" },
    { "-pruserdrv", SET_RESOURCE, 1, NULL, NULL, "PrinterUserportDriver", NULL,
     "<name>", "Specify name of printer driver for the userport printer" },
    { NULL }
};

int driver_select_init_cmdline_options(void)
{
    return cmdline_register_options(cmdline_options);
}


void driver_select_init(void)
{

}

/* ------------------------------------------------------------------------- */

void driver_select_register(driver_select_t *driver_select)
{
    driver_select_list_t *list, *prev;

    prev = driver_select_list;
    while (prev != NULL && prev->next != NULL)
        prev = prev->next;

    list = (driver_select_list_t *)xmalloc(sizeof(driver_select_list_t));
    memcpy(&(list->driver_select), driver_select, sizeof(driver_select_t));
    list->next = NULL;

    if (driver_select_list != NULL)
        prev->next = list;
    else
        driver_select_list = list;
}

/* ------------------------------------------------------------------------- */

int driver_select_open(unsigned int prnr, unsigned int secondary)
{
    return driver_select[prnr].drv_open(prnr, secondary);
}

void driver_select_close(unsigned int prnr, unsigned int secondary)
{
    driver_select[prnr].drv_close(prnr, secondary);
}

int driver_select_putc(unsigned int prnr, unsigned int secondary, BYTE b)
{
    return driver_select[prnr].drv_putc(prnr, secondary, b);
}

int driver_select_getc(unsigned int prnr, unsigned int secondary, BYTE *b)
{
    return driver_select[prnr].drv_getc(prnr, secondary, b);
}

int driver_select_flush(unsigned int prnr, unsigned int secondary)
{
    return driver_select[prnr].drv_flush(prnr, secondary);
}

