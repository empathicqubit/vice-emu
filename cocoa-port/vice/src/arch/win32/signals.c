/*
 * signals.c
 *
 * Written by
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

#include <stdlib.h>

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "log.h"
#include "monitor.h"
#include "res.h"
#include "signals.h"
#include "translate.h"
#include "ui.h"


static const char * translated_text = "An unexpected error occurred. Received signal %d (%s).";

static void get_translated_text(void)
{
    const char * new_translated_text;

    new_translated_text = translate_text(IDS_RECEIVED_SIGNAL_D_S);

    if (new_translated_text != 0 && *new_translated_text != 0) {
        translated_text = new_translated_text;
    }
}

static RETSIGTYPE break64(int sig)
{
    const char * signalname = "";

    get_translated_text();

    /* provide a default text in case we could not translated the text. */

#ifdef SYS_SIGLIST_DECLARED
    signalname = sys_siglist[sig]
#endif

    ui_error(translated_text, sig, signalname);

    exit(-1);
}

void signals_init(int do_core_dumps)
{
    signal(SIGINT, break64);
    signal(SIGTERM, break64);

    if (!do_core_dumps) {

        get_translated_text();

        signal(SIGSEGV, break64);
        signal(SIGILL, break64);
        signal(SIGFPE, break64);
    }
}

typedef void (*signal_handler_t)(int);

static signal_handler_t old_handler;

static void handle_abort(int signo)
{
    monitor_abort();
    signal(SIGINT, (signal_handler_t)handle_abort);
}

void signals_abort_set(void)
{
    old_handler = signal(SIGINT, handle_abort);
}

void signals_abort_unset(void)
{
    signal(SIGINT, old_handler);
}

