/*
 * Copyright (c) 2012 Clément Bœsch
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

/**
 * @file
 * WebVTT subtitle decoder
 * @see http://dev.w3.org/html5/webvtt/
 * @todo need to support extended markups and cue settings
 */

#include "avcodec.h"
#include "ass.h"
#include "libavutil/bprint.h"

static const struct {
    const char *from;
    const char *to;
} webvtt_tag_replace[] = {
    {"<i>", "{\\i1}"}, {"</i>", "{\\i0}"},
    {"<b>", "{\\b1}"}, {"</b>", "{\\b0}"},
    {"<u>", "{\\u1}"}, {"</u>", "{\\u0}"},
    {"{", "\\{"}, {"}", "\\}"}, // escape to avoid ASS markup conflicts
};

static int webvtt_event_to_ass(AVBPrint *buf, const char *p)
{
    int i, skip = 0;

    while (*p) {

        for (i = 0; i < FF_ARRAY_ELEMS(webvtt_tag_replace); i++) {
            const char *from = webvtt_tag_replace[i].from;
            const size_t len = strlen(from);
            if (!strncmp(p, from, len)) {
                av_bprintf(buf, "%s", webvtt_tag_replace[i].to);
                p += len;
                break;
            }
        }
        if (!*p)
            break;

        if (*p == '<')
            skip = 1;
        else if (*p == '>')
            skip = 0;
        else if (p[0] == '\n' && p[1])
            av_bprintf(buf, "\\N");
        else if (!skip && *p != '\r')
            av_bprint_chars(buf, *p, 1);
        p++;
    }
    av_bprintf(buf, "\r\n");
    return 0;
}

static int webvtt_decode_frame(AVCodecContext *avctx,
                               void *data, int *got_sub_ptr, AVPacket *avpkt)
{
    AVSubtitle *sub = data;
    const char *ptr = avpkt->data;
    AVBPrint buf;

    av_bprint_init(&buf, 0, AV_BPRINT_SIZE_UNLIMITED);
    if (ptr && avpkt->size > 0 && !webvtt_event_to_ass(&buf, ptr)) {
		int ts_start     = av_rescale_q(avpkt->pts, avctx->time_base, (AVRational){1,100});
        int ts_duration  = avpkt->duration != -1 ?
                           av_rescale_q(avpkt->duration, avctx->time_base, (AVRational){1,100}) : -1;
		ff_ass_add_rect(sub, buf.str, ts_start, ts_duration, 0);
    }
    *got_sub_ptr = sub->num_rects > 0;
    av_bprint_finalize(&buf, NULL);
    return avpkt->size;
}

AVCodec ff_webvtt_decoder = {
	.name           = "webvtt",
    .long_name      = NULL_IF_CONFIG_SMALL("WebVTT subtitle"),
    .type           = AVMEDIA_TYPE_SUBTITLE,
    .id             = AV_CODEC_ID_WEBVTT,
    .decode         = webvtt_decode_frame,
    .init           = ff_ass_subtitle_header_default,
};
