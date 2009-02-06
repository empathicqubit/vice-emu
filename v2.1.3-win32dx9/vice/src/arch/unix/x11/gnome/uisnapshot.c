/*
 * uisnapshot.c - Snapshot dialog for the Gnome widget set.
 *
 * Written by
 *  pottendo <pottendo@gmx.net>
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

#include "uisnapshot.h"
#include "ui.h"
#include "uiarch.h"
#include "machine.h"
#include "uifileentry.h"
#include "lib.h"

static GtkWidget *snapshot_dialog, *attach_disk, *attach_rom, *fileentry;

static GtkWidget *build_snapshot_dialog(void)
{
    GtkWidget *d, *box, *tmp;
    
    d = gtk_dialog_new_with_buttons(_("Save Snapshot"), 
			 NULL,
			 GTK_DIALOG_DESTROY_WITH_PARENT,
			 GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
			 GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			 NULL);
    box = gtk_hbox_new(0, FALSE);

    fileentry = vice_file_entry(_("Save Snapshot"), NULL, "*.vsf", 
				GTK_FILE_CHOOSER_ACTION_SAVE);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_ACCEPT);
    
    gtk_box_pack_start(GTK_BOX(box), fileentry, TRUE, TRUE, 0);
    gtk_widget_show(fileentry);
    
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(d)->vbox), box, TRUE, TRUE, 0);
    gtk_widget_show(box);
    
    tmp = gtk_frame_new(_("Snapshot options"));
    box = gtk_vbox_new(0, FALSE);
    
    attach_disk = 
	gtk_check_button_new_with_label(_("Save currently attached disks"));
    gtk_box_pack_start(GTK_BOX(box), attach_disk, FALSE, FALSE, 0);
    gtk_widget_show(attach_disk);

    attach_rom = 
	gtk_check_button_new_with_label(_("Save currently attached ROMs"));
    gtk_box_pack_start(GTK_BOX(box), attach_rom, FALSE, FALSE, 0);
    gtk_widget_show(attach_rom);
    
    gtk_container_add(GTK_CONTAINER(tmp), box);
    gtk_widget_show(box);
    
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(d)->vbox), tmp, TRUE, TRUE, 
		       0);
    gtk_widget_show(tmp);
    
    return d;
}

void ui_snapshot_dialog(void)
{
    gint res;
    char *name;
    
    if (snapshot_dialog)
    {
	gdk_window_show(snapshot_dialog->window);
	gdk_window_raise(snapshot_dialog->window);
	gtk_widget_show(snapshot_dialog);
    }
    else
    {
	snapshot_dialog = build_snapshot_dialog();
	g_signal_connect(G_OBJECT(snapshot_dialog),
			 "destroy",
			 G_CALLBACK(gtk_widget_destroyed),
			 &snapshot_dialog);
    }

    ui_popup(snapshot_dialog, "Save Snapshot", FALSE);
    res = gtk_dialog_run(GTK_DIALOG(snapshot_dialog));
    ui_popdown(snapshot_dialog);
    
    if (res != GTK_RESPONSE_ACCEPT)
	return;
    
    name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fileentry));
    if (!name)
    {
	ui_error(_("Invalid filename"));
	return;
    }
    
    /* ok button pressed */
    if (machine_write_snapshot(name, GTK_TOGGLE_BUTTON(attach_rom)->active, 
			       GTK_TOGGLE_BUTTON(attach_disk)->active, 0) < 0)
        ui_error(_("Cannot write snapshot file\n`%s'\n"), name);
    else
	ui_message(_("Successfully wrote `%s'\n"), name);
    lib_free(name);
}

