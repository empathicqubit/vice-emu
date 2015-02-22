/*
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

#include "libavutil/avstring.h"
#include "libavutil/common.h"
#include "libavutil/internal.h"
#include "libavutil/opt.h"
#include "libavutil/pixdesc.h"
#include "libavutil/pixfmt.h"

#include "avfilter.h"
#include "internal.h"
#include "video.h"

typedef struct ShufflePlanesContext {
    const AVClass *class;

    /* number of planes in the selected pixel format */
    int planes;

    /* mapping indices */
    int map[4];

    /* set to 1 if some plane is used more than once, so we need to make a copy */
    int copy;
} ShufflePlanesContext;

static av_cold int shuffleplanes_config_input(AVFilterLink *inlink)
{
    AVFilterContext    *ctx = inlink->dst;
    ShufflePlanesContext *s = ctx->priv;
    const AVPixFmtDescriptor *desc;
    int used[4] = { 0 };
    int i;

    s->copy   = 0;
    s->planes = av_pix_fmt_count_planes(inlink->format);
    desc      = av_pix_fmt_desc_get(inlink->format);

    for (i = 0; i < s->planes; i++) {
        if (s->map[i] >= s->planes) {
            av_log(ctx, AV_LOG_ERROR,
                   "Non-existing input plane #%d mapped to output plane #%d.\n",
                   s->map[i], i);
            return AVERROR(EINVAL);
        }

        if ((desc->log2_chroma_h || desc->log2_chroma_w) &&
            (i == 1 || i == 2) != (s->map[i] == 1 || s->map[i] == 2)) {
            av_log(ctx, AV_LOG_ERROR,
                   "Cannot map between a subsampled chroma plane and a luma "
                   "or alpha plane.\n");
            return AVERROR(EINVAL);
        }

        if ((desc->flags & AV_PIX_FMT_FLAG_PAL ||
             desc->flags & AV_PIX_FMT_FLAG_PSEUDOPAL) &&
            (i == 1) != (s->map[i] == 1)) {
            av_log(ctx, AV_LOG_ERROR,
                   "Cannot map between a palette plane and a data plane.\n");
            return AVERROR(EINVAL);
        }
        if (used[s->map[i]])
            s->copy = 1;
        used[s->map[i]]++;
    }

    return 0;
}

static int shuffleplanes_filter_frame(AVFilterLink *inlink, AVFrame *frame)
{
    AVFilterContext          *ctx = inlink->dst;
    ShufflePlanesContext       *s = ctx->priv;
    uint8_t *shuffled_data[4]     = { NULL };
    int      shuffled_linesize[4] = { 0 };
    int i, ret;

    for (i = 0; i < s->planes; i++) {
        shuffled_data[i]     = frame->data[s->map[i]];
        shuffled_linesize[i] = frame->linesize[s->map[i]];
    }
    memcpy(frame->data,     shuffled_data,     sizeof(shuffled_data));
    memcpy(frame->linesize, shuffled_linesize, sizeof(shuffled_linesize));

    if (s->copy) {
        AVFrame *copy = ff_get_video_buffer(ctx->outputs[0], frame->width, frame->height);

        if (!copy) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }

        av_frame_copy(copy, frame);

        ret = av_frame_copy_props(copy, frame);
        if (ret < 0) {
            av_frame_free(&copy);
            goto fail;
        }

        av_frame_free(&frame);
        frame = copy;
    }

    return ff_filter_frame(ctx->outputs[0], frame);
fail:
    av_frame_free(&frame);
    return ret;
}

#define OFFSET(x) offsetof(ShufflePlanesContext, x)
#define FLAGS (AV_OPT_FLAG_FILTERING_PARAM | AV_OPT_FLAG_VIDEO_PARAM)
static const AVOption shuffleplanes_options[] = {
    { "map0", "Index of the input plane to be used as the first output plane ",  OFFSET(map[0]), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, 4, FLAGS },
    { "map1", "Index of the input plane to be used as the second output plane ", OFFSET(map[1]), AV_OPT_TYPE_INT, { .i64 = 1 }, 0, 4, FLAGS },
    { "map2", "Index of the input plane to be used as the third output plane ",  OFFSET(map[2]), AV_OPT_TYPE_INT, { .i64 = 2 }, 0, 4, FLAGS },
    { "map3", "Index of the input plane to be used as the fourth output plane ", OFFSET(map[3]), AV_OPT_TYPE_INT, { .i64 = 3 }, 0, 4, FLAGS },
    { NULL },
};

static const AVClass shuffleplanes_class = {
    .class_name = "shuffleplanes",
    .item_name  = av_default_item_name,
    .option     = shuffleplanes_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

static const AVFilterPad shuffleplanes_inputs[] = {
    {
        .name             = "default",
        .type             = AVMEDIA_TYPE_VIDEO,
        .config_props     = shuffleplanes_config_input,
        .filter_frame     = shuffleplanes_filter_frame,
        .get_video_buffer = ff_null_get_video_buffer,
    },
    { NULL },
};

static const AVFilterPad shuffleplanes_outputs[] = {
    {
        .name = "default",
        .type = AVMEDIA_TYPE_VIDEO,
    },
    { NULL },
};

AVFilter ff_vf_shuffleplanes = {
    .name         = "shuffleplanes",
    .description  = NULL_IF_CONFIG_SMALL("Shuffle video planes"),

    .priv_size    = sizeof(ShufflePlanesContext),
    .priv_class   = &shuffleplanes_class,

    .inputs       = shuffleplanes_inputs,
    .outputs      = shuffleplanes_outputs,
};
