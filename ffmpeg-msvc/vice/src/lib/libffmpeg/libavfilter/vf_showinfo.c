/*
 * Copyright (c) 2011 Stefano Sabatini
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
 * filter for showing textual video frame information
 */

#include <inttypes.h>

#include "libavutil/adler32.h"
#include "libavutil/display.h"
#include "libavutil/imgutils.h"
#include "libavutil/internal.h"
#include "libavutil/pixdesc.h"
#include "libavutil/stereo3d.h"
#include "libavutil/timestamp.h"

#include "avfilter.h"
#include "internal.h"
#include "video.h"

static void dump_stereo3d(AVFilterContext *ctx, AVFrameSideData *sd)
{
    AVStereo3D *stereo;

    av_log(ctx, AV_LOG_INFO, "stereoscopic information: ");
    if (sd->size < sizeof(*stereo)) {
        av_log(ctx, AV_LOG_INFO, "invalid data");
        return;
    }

    stereo = (AVStereo3D *)sd->data;

    av_log(ctx, AV_LOG_INFO, "type - ");
    switch (stereo->type) {
    case AV_STEREO3D_2D:                  av_log(ctx, AV_LOG_INFO, "2D");                     break;
    case AV_STEREO3D_SIDEBYSIDE:          av_log(ctx, AV_LOG_INFO, "side by side");           break;
    case AV_STEREO3D_TOPBOTTOM:           av_log(ctx, AV_LOG_INFO, "top and bottom");         break;
    case AV_STEREO3D_FRAMESEQUENCE:       av_log(ctx, AV_LOG_INFO, "frame alternate");        break;
    case AV_STEREO3D_CHECKERBOARD:        av_log(ctx, AV_LOG_INFO, "checkerboard");           break;
    case AV_STEREO3D_LINES:               av_log(ctx, AV_LOG_INFO, "interleaved lines");      break;
    case AV_STEREO3D_COLUMNS:             av_log(ctx, AV_LOG_INFO, "interleaved columns");    break;
    case AV_STEREO3D_SIDEBYSIDE_QUINCUNX: av_log(ctx, AV_LOG_INFO, "side by side "
                                                                   "(quincunx subsampling)"); break;
    default:                              av_log(ctx, AV_LOG_WARNING, "unknown");             break;
    }

    if (stereo->flags & AV_STEREO3D_FLAG_INVERT)
        av_log(ctx, AV_LOG_INFO, " (inverted)");
}

static void update_sample_stats(const uint8_t *src, int len, int64_t *sum, int64_t *sum2)
{
    int i;

    for (i = 0; i < len; i++) {
        *sum += src[i];
        *sum2 += src[i] * src[i];
    }
}

static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
{
    AVFilterContext *ctx = inlink->dst;
    const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(inlink->format);
    uint32_t plane_checksum[4] = {0}, checksum = 0;
    int64_t sum[4] = {0}, sum2[4] = {0};
    int32_t pixelcount[4] = {0};
    int i, plane, vsub = desc->log2_chroma_h;
#ifdef IDE_COMPILE
	char tmp1[32] = {0};
	char tmp2[32] = {0};
#endif

    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
        int64_t linesize = av_image_get_linesize(frame->format, frame->width, plane);
        uint8_t *data = frame->data[plane];
        int h = plane == 1 || plane == 2 ? FF_CEIL_RSHIFT(inlink->h, vsub) : inlink->h;

        if (linesize < 0)
            return linesize;

        for (i = 0; i < h; i++) {
            plane_checksum[plane] = av_adler32_update(plane_checksum[plane], data, linesize);
            checksum = av_adler32_update(checksum, data, linesize);

            update_sample_stats(data, linesize, sum+plane, sum2+plane);
            pixelcount[plane] += linesize;
            data += frame->linesize[plane];
        }
    }

#ifdef IDE_COMPILE
	av_log(ctx, AV_LOG_INFO,
           "n:%"PRId64" pts:%s pts_time:%s pos:%"PRId64" "
           "fmt:%s sar:%d/%d s:%dx%d i:%c iskey:%d type:%c "
           "checksum:%08"PRIX32" plane_checksum:[%08"PRIX32,
           inlink->frame_count,
           av_ts_make_string(tmp1, frame->pts), av_ts_make_time_string(tmp2, frame->pts, &inlink->time_base), av_frame_get_pkt_pos(frame),
           desc->name,
           frame->sample_aspect_ratio.num, frame->sample_aspect_ratio.den,
           frame->width, frame->height,
           !frame->interlaced_frame ? 'P' :         /* Progressive  */
           frame->top_field_first   ? 'T' : 'B',    /* Top / Bottom */
           frame->key_frame,
           av_get_picture_type_char(frame->pict_type),
           checksum, plane_checksum[0]);
#else
	av_log(ctx, AV_LOG_INFO,
           "n:%"PRId64" pts:%s pts_time:%s pos:%"PRId64" "
           "fmt:%s sar:%d/%d s:%dx%d i:%c iskey:%d type:%c "
           "checksum:%08"PRIX32" plane_checksum:[%08"PRIX32,
           inlink->frame_count,
           av_ts2str(frame->pts), av_ts2timestr(frame->pts, &inlink->time_base), av_frame_get_pkt_pos(frame),
           desc->name,
           frame->sample_aspect_ratio.num, frame->sample_aspect_ratio.den,
           frame->width, frame->height,
           !frame->interlaced_frame ? 'P' :         /* Progressive  */
           frame->top_field_first   ? 'T' : 'B',    /* Top / Bottom */
           frame->key_frame,
           av_get_picture_type_char(frame->pict_type),
           checksum, plane_checksum[0]);
#endif

    for (plane = 1; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++)
        av_log(ctx, AV_LOG_INFO, " %08"PRIX32, plane_checksum[plane]);
    av_log(ctx, AV_LOG_INFO, "] mean:[");
    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++)
        av_log(ctx, AV_LOG_INFO, "%"PRId64" ", (sum[plane] + pixelcount[plane]/2) / pixelcount[plane]);
    av_log(ctx, AV_LOG_INFO, "\b] stdev:[");
    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++)
        av_log(ctx, AV_LOG_INFO, "%3.1f ",
               sqrt((sum2[plane] - sum[plane]*(double)sum[plane]/pixelcount[plane])/pixelcount[plane]));
    av_log(ctx, AV_LOG_INFO, "\b]\n");

    for (i = 0; i < frame->nb_side_data; i++) {
        AVFrameSideData *sd = frame->side_data[i];

        av_log(ctx, AV_LOG_INFO, "  side data - ");
        switch (sd->type) {
        case AV_FRAME_DATA_PANSCAN:
            av_log(ctx, AV_LOG_INFO, "pan/scan");
            break;
        case AV_FRAME_DATA_A53_CC:
            av_log(ctx, AV_LOG_INFO, "A/53 closed captions (%d bytes)", sd->size);
            break;
        case AV_FRAME_DATA_STEREO3D:
            dump_stereo3d(ctx, sd);
            break;
        case AV_FRAME_DATA_DISPLAYMATRIX:
            av_log(ctx, AV_LOG_INFO, "displaymatrix: rotation of %.2f degrees",
                   av_display_rotation_get((int32_t *)sd->data));
            break;
        case AV_FRAME_DATA_AFD:
            av_log(ctx, AV_LOG_INFO, "afd: value of %"PRIu8, sd->data[0]);
            break;
        default:
            av_log(ctx, AV_LOG_WARNING, "unknown side data type %d (%d bytes)",
                   sd->type, sd->size);
            break;
        }

        av_log(ctx, AV_LOG_INFO, "\n");
    }

    return ff_filter_frame(inlink->dst->outputs[0], frame);
}

static const AVFilterPad avfilter_vf_showinfo_inputs[] = {
    {
#ifdef IDE_COMPILE
        "default",
        AVMEDIA_TYPE_VIDEO,
        0, 0, 0, 0, 0, 0, 0, filter_frame,
#else
		.name         = "default",
        .type         = AVMEDIA_TYPE_VIDEO,
        .filter_frame = filter_frame,
#endif
	},
    { NULL }
};

static const AVFilterPad avfilter_vf_showinfo_outputs[] = {
    {
#ifdef IDE_COMPILE
        "default",
        AVMEDIA_TYPE_VIDEO
#else
		.name = "default",
        .type = AVMEDIA_TYPE_VIDEO
#endif
	},
    { NULL }
};

AVFilter ff_vf_showinfo = {
#ifdef IDE_COMPILE
    "showinfo",
    NULL_IF_CONFIG_SMALL("Show textual information for each video frame."),
    avfilter_vf_showinfo_inputs,
    avfilter_vf_showinfo_outputs,
#else
	.name        = "showinfo",
    .description = NULL_IF_CONFIG_SMALL("Show textual information for each video frame."),
    .inputs      = avfilter_vf_showinfo_inputs,
    .outputs     = avfilter_vf_showinfo_outputs,
#endif
};
