/*
 * uimon.m - MacVICE monitor interface
 *
 * Written by
 *  Christian Vogelgsang <chris@vogelgsang.org>
 *  Michael Klein <michael.klein@puffin.lb.shuttle.de>
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
#include "console.h"
#include "lib.h"
#include "monitor.h"
#include "uimon.h"

#import "vicemachine.h"

static console_t dummy = { 80,25,1,0,NULL };

console_t *uimon_window_open( void )
{
    // open monitor window
    [[theVICEMachine app] openMonitor];
    return &dummy;
}

void uimon_window_close( void )
{
    // close monitor window
    [[theVICEMachine app] closeMonitor];
}

void uimon_window_suspend( void )
{
    // monitor is temporarly suspended. disable UI of monitor
}

console_t *uimon_window_resume( void )
{
    // monitor is activated after suspend. reenabled UI of monitor.
    return &dummy;
}

int uimon_out(const char *buffer)
{
    [[theVICEMachine app] printMonitorMessage:[NSString stringWithCString:buffer encoding:NSUTF8StringEncoding]];
    return 0;
}

char *uimon_get_in(char **ppchCommandLine, const char *prompt)
{
    NSString *line = [[theVICEMachine app] readMonitorLine:[NSString stringWithCString:prompt encoding:NSUTF8StringEncoding]];
    char *ret;
    if(line==nil)
        ret = lib_stralloc("");
    else
        ret = lib_stralloc([line cStringUsingEncoding:NSUTF8StringEncoding]);
    return ret;
}

void uimon_notify_change( void )
{
}

void uimon_set_interface(monitor_interface_t **monitor_interface_init,
                         int count )
{
}

