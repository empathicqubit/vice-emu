/*
 * SSA/ASS common functions
 * Copyright (c) 2010  Aurelien Jacobs <aurel@gnuage.org>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "avcodec.h"
#include "ass.h"
#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/bprint.h"
#include "libavutil/common.h"

int ff_ass_subtitle_header(AVCodecContext *avctx,
                           const char *font, int font_size,
                           int color, int back_color,
                           int bold, int italic, int underline,
                           int alignment)
{
    avctx->subtitle_header = av_asprintf(
             "[Script Info]\r\n"
             "ScriptType: v4.00+\r\n"
             "PlayResX: 384\r\n"
             "PlayResY: 288\r\n"
             "\r\n"
             "[V4+ Styles]\r\n"
             "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, AlphaLevel, Encoding\r\n"
             "Style: Default,%s,%d,&H%x,&H%x,&H%x,&H%x,%d,%d,%d,1,1,0,%d,10,10,10,0,0\r\n"
             "\r\n"
             "[Events]\r\n"
             "Format: Layer, Start, End, Style, Text\r\n",
             font, font_size, color, color, back_color, back_color,
             -bold, -italic, -underline, alignment);

    if (!avctx->subtitle_header)
        return AVERROR(ENOMEM);
    avctx->subtitle_header_size = strlen(avctx->subtitle_header);
    return 0;
}

int ff_ass_subtitle_header_default(AVCodecContext *avctx)
{
    return ff_ass_subtitle_header(avctx, ASS_DEFAULT_FONT,
                               ASS_DEFAULT_FONT_SIZE,
                               ASS_DEFAULT_COLOR,
                               ASS_DEFAULT_BACK_COLOR,
                               ASS_DEFAULT_BOLD,
                               ASS_DEFAULT_ITALIC,
                               ASS_DEFAULT_UNDERLINE,
                               ASS_DEFAULT_ALIGNMENT);
}

static void insert_ts(AVBPrint *buf, int ts)
{
    if (ts == -1) {
        av_bprintf(buf, "9:59:59.99,");
    } else {
        int h, m, s;

        h = ts/360000;  ts -= 360000*h;
        m = ts/  6000;  ts -=   6000*m;
        s = ts/   100;  ts -=    100*s;
        av_bprintf(buf, "%d:%02d:%02d.%02d,", h, m, s, ts);
    }
}

int ff_ass_bprint_dialog(AVBPrint *buf, const char *dialog,
                         int ts_start, int duration, int raw)
{
    int dlen;

    if (!raw || raw == 2) {
        long int layer = 0;

        if (raw == 2) {
            /* skip ReadOrder */
            dialog = strchr(dialog, ',');
            if (!dialog)
                return AVERROR_INVALIDDATA;
            dialog++;

            /* extract Layer or Marked */
            layer = strtol(dialog, (char**)&dialog, 10);
            if (*dialog != ',')
                return AVERROR_INVALIDDATA;
            dialog++;
        }
        av_bprintf(buf, "Dialogue: %ld,", layer);
        insert_ts(buf, ts_start);
        insert_ts(buf, duration == -1 ? -1 : ts_start + duration);
        if (raw != 2)
            av_bprintf(buf, "Default,");
    }

    dlen = strcspn(dialog, "\n");
    dlen += dialog[dlen] == '\n';

    av_bprintf(buf, "%.*s", dlen, dialog);
    if (raw == 2)
        av_bprintf(buf, "\r\n");

    return dlen;
}

int ff_ass_add_rect(AVSubtitle *sub, const char *dialog,
                    int ts_start, int duration, int raw)
{
    AVBPrint buf;
    int ret, dlen;
    AVSubtitleRect **rects;

    av_bprint_init(&buf, 0, AV_BPRINT_SIZE_UNLIMITED);
    if ((ret = ff_ass_bprint_dialog(&buf, dialog, ts_start, duration, raw)) < 0)
        goto err;
    dlen = ret;
    if (!av_bprint_is_complete(&buf))
        goto errnomem;

    rects = av_realloc(sub->rects, (sub->num_rects+1) * sizeof(*sub->rects));
    if (!rects)
        goto errnomem;
    sub->rects = rects;
    sub->end_display_time = FFMAX(sub->end_display_time, 10 * duration);
    rects[sub->num_rects]       = av_mallocz(sizeof(*rects[0]));
    rects[sub->num_rects]->type = SUBTITLE_ASS;
    ret = av_bprint_finalize(&buf, &rects[sub->num_rects]->ass);
    if (ret < 0)
        goto err;
    sub->num_rects++;
    return dlen;

errnomem:
    ret = AVERROR(ENOMEM);
err:
    av_bprint_finalize(&buf, NULL);
    return ret;
}

void ff_ass_bprint_text_event(AVBPrint *buf, const char *p, int size,
                             const char *linebreaks, int keep_ass_markup)
{
    const char *p_end = p + size;

    for (; p < p_end && *p; p++) {

        /* forced custom line breaks, not accounted as "normal" EOL */
        if (linebreaks && strchr(linebreaks, *p)) {
            av_bprintf(buf, "\\N");

        /* standard ASS escaping so random characters don't get mis-interpreted
         * as ASS */
        } else if (!keep_ass_markup && strchr("{}\\", *p)) {
            av_bprintf(buf, "\\%c", *p);

        /* some packets might end abruptly (no \0 at the end, like for example
         * in some cases of demuxing from a classic video container), some
         * might be terminated with \n or \r\n which we have to remove (for
         * consistency with those who haven't), and we also have to deal with
         * evil cases such as \r at the end of the buffer (and no \0 terminated
         * character) */
        } else if (p[0] == '\n') {
            /* some stuff left so we can insert a line break */
            if (p < p_end - 1)
                av_bprintf(buf, "\\N");
        } else if (p[0] == '\r' && p < p_end - 1 && p[1] == '\n') {
            /* \r followed by a \n, we can skip it. We don't insert the \N yet
             * because we don't know if it is followed by more text */
            continue;

        /* finally, a sane character */
        } else {
            av_bprint_chars(buf, *p, 1);
        }
    }
    av_bprintf(buf, "\r\n");
}
