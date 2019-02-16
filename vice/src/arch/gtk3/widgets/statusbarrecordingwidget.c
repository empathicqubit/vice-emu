/** \file   statusbarrecordingwidget.c
 * \brief   Widget to display and control recording of events/audio/video
 *
 * \author  Bas Wassink <b.wassink@ziggo.nl>
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
 */


#include "vice.h"
#include <gtk/gtk.h>
#include "vice_gtk3.h"
#include "basedialogs.h"
#include "vice-event.h"
#include "machine.h"
#include "resources.h"
#include "screenshot.h"
#include "sound.h"
#include "ui.h"
#include "uimedia.h"

#include "statusbarrecordingwidget.h"


/** \brief  Columns in the recording widget
 */
enum {
    RW_COL_TEXT = 0,    /**< recording status label */
    RW_COL_TIME = 0,    /**< recording time label */
    RW_COL_BUTTON = 1   /**< STOP button */
};


/** \brief  Rows in the recording widget
 */
enum {
    RW_ROW_TEXT = 0,    /**< recording status label */
    RW_ROW_TIME = 1,    /**< recording time label */
    RW_ROW_BUTTON = 0   /**< STOP button (takes both rows) */
};


/** \brief  Types of recordings
 */
enum {
    RW_TYPE_NONE,   /**< nothing is being recorded */
    RW_TYPE_EVENTS, /**< recording events */
    RW_TYPE_AUDIO,  /**< recording audio */
    RW_TYPE_VIDEO   /**< recording video */
};


/** \brief  Types of recordings as strings
 */
static const gchar *rec_types[] = {
    "inactive",
    "events",
    "audio",
    "video"
};


/** \brief  Event handler for the 'clicked' event of the STOP button
 *
 * Stops all recordings.
 *
 * \param[in,out]   button  button triggering the event
 * \param[im,out]   data    statusbar recording widget (GtkGrid)
 */
static void on_stop_clicked(GtkWidget *button, gpointer data)
{
    GtkWidget *label;

    uimedia_stop_recording(button, NULL);
    if (event_record_active()) {
        event_record_stop();
    }

    label = gtk_grid_get_child_at(GTK_GRID(data), RW_COL_TEXT, RW_ROW_TEXT);
    gtk_label_set_text(GTK_LABEL(label), "Recording stopped.");
}


/** \brief  Create recording status widget
 *
 * Generate a widget to show on the statusbar to display recording state
 *
 * \return  GtkGrid
 */
GtkWidget *statusbar_recording_widget_create(void)
{
    GtkWidget *grid;
    GtkWidget *label;
    GtkWidget *button;

    grid = vice_gtk3_grid_new_spaced(8, 8);
    gtk_widget_set_hexpand(grid, TRUE);

    /* recording status label */
    label = gtk_label_new("Recording widget, not quite finished.");
    gtk_grid_attach(GTK_GRID(grid), label, RW_COL_TEXT, RW_ROW_TEXT, 1, 1);
    gtk_widget_set_halign(label, GTK_ALIGN_FILL);
    gtk_widget_set_hexpand(label, TRUE);

    /* recording timestamp label */
    label = gtk_label_new("00:00 / 00:00");
    gtk_widget_set_halign(label, GTK_ALIGN_FILL);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_grid_attach(GTK_GRID(grid), label, RW_COL_TIME, RW_ROW_TIME, 1, 1);

    button = gtk_button_new_from_icon_name("media-playback-stop",
                                           GTK_ICON_SIZE_LARGE_TOOLBAR);
    gtk_grid_attach(GTK_GRID(grid), button, RW_COL_BUTTON, RW_ROW_BUTTON, 1, 2);
    gtk_widget_set_halign(button, GTK_ALIGN_END);
    gtk_widget_set_hexpand(button, FALSE);
    gtk_widget_set_sensitive(button, FALSE);
    g_signal_connect(button, "clicked", G_CALLBACK(on_stop_clicked),
           (gpointer)grid);
    return grid;
}


/** \brief  Set recording status
 *
 * Sets the type of recording and the status (ie 'Recording $rec-type or
 * 'Recording stopped).
 *
 * \note    Somehow getting the recording state of events doesn't work yet,
 *          so that currently displays 'inactive'.
 *
 * \param[in,out]   widget  statusbar recording status widget
 * \param[in]       status  recording status (boolean)
 */
void statusbar_recording_widget_set_recording_status(GtkWidget *widget,
                                                     int status)
{
    GtkWidget *label;
    gchar buffer[256];
    GtkWidget *button;
    int type = 0;   /* set recording type to 'inactive' */

    /* determine recording type */
    if (event_record_active()) {
        /* XXX: doesn't work for some obscure reason
         *
         * When triggering the menu item 'start event recording' again, we do
         * get "Recording events", so it looks like the event recording state
         * is set after events.c calls ui_display_recording().
         */
        type = RW_TYPE_EVENTS;
    } else if (sound_is_recording()) {
        type = RW_TYPE_AUDIO;
    } else if (screenshot_is_recording()) {
        type = RW_TYPE_VIDEO;
    }


    /* update recording status text */
    label = gtk_grid_get_child_at(GTK_GRID(widget), RW_COL_TEXT, RW_ROW_TEXT);
    g_snprintf(buffer, 256, "Recording %s ...", rec_types[type]);
    gtk_label_set_text(GTK_LABEL(label), buffer);

    /* enable/disable STOP butto based on the \a status variable */
    button = gtk_grid_get_child_at(
            GTK_GRID(widget), RW_COL_BUTTON, RW_ROW_BUTTON);
    gtk_widget_set_tooltip_text(button, "Stop recording");
    gtk_widget_set_sensitive(button, status);
}


/** \brief  Update recording/playback time display
 *
 * \param[in,out]   statusbar   recording widget
 * \param[in]       current     current time in seconds
 * \param[in]       total       total time in seconds
 *
 * \note    \a total only makes sense when replaying events.
 *          I could make the time display '--:--' when \a total is 0, but it
 *          it possible, though unlikely, we're replaying a sequence of events
 *          which take less than a second.
 */
void statusbar_recording_widget_set_time(GtkWidget *widget,
                                         unsigned int current,
                                         unsigned int total)
{
    GtkWidget *label;
    gchar buffer[256];

    label = gtk_grid_get_child_at(GTK_GRID(widget), RW_COL_TIME, RW_ROW_TIME);
    g_snprintf(buffer, 256, "Time: %02u:%02u / %02u:%02u",
            current / 60, current % 60, total / 60, total % 60);
    gtk_label_set_text(GTK_LABEL(label), buffer);
}
