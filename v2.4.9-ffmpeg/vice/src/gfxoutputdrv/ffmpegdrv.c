/*
 * ffmpegdrv.c - Movie driver using FFMPEG library and screenshot API.
 *
 * Written by
 *  Andreas Matthies <andreas.matthies@gmx.net>
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

#ifdef HAVE_FFMPEG

#include <stdio.h>
#include <string.h>

#include "archdep.h"
#include "cmdline.h"
#include "ffmpegdrv.h"
#include "ffmpeglib.h"
#include "gfxoutput.h"
#include "lib.h"
#include "log.h"
#include "machine.h"
#include "palette.h"
#include "resources.h"
#include "screenshot.h"
#include "translate.h"
#include "uiapi.h"
#include "util.h"
#include "../sounddrv/soundmovie.h"

static gfxoutputdrv_codec_t avi_audio_codeclist[] = {
    { AV_CODEC_ID_MP2, "MP2" },
    { AV_CODEC_ID_MP3, "MP3" },
    { AV_CODEC_ID_FLAC, "FLAC" },
    { AV_CODEC_ID_PCM_S16LE, "PCM uncompressed" },
    { 0, NULL }
};

static gfxoutputdrv_codec_t mp4_audio_codeclist[] = {
    { AV_CODEC_ID_MP3, "MP3" },
    { AV_CODEC_ID_AAC, "AAC" },
    { AV_CODEC_ID_AC3, "AC3" },
    { AV_CODEC_ID_PCM_S16LE, "PCM uncompressed" },
    { 0, NULL }
};

static gfxoutputdrv_codec_t avi_video_codeclist[] = {
    { AV_CODEC_ID_MPEG4, "MPEG4 (DivX)" },
    { AV_CODEC_ID_MPEG1VIDEO, "MPEG1" },
    { AV_CODEC_ID_FFV1, "FFV1 (lossless)" },
    { AV_CODEC_ID_H264, "H264" },
    { AV_CODEC_ID_THEORA, "Theora" },
    { 0, NULL }
};

static gfxoutputdrv_codec_t mp4_video_codeclist[] = {
    { AV_CODEC_ID_H264, "H264" },
    { 0, NULL }
};

static gfxoutputdrv_codec_t ogg_audio_codeclist[] = {
    { AV_CODEC_ID_FLAC, "FLAC" },
    { 0, NULL }
};

static gfxoutputdrv_codec_t ogg_video_codeclist[] = {
    { AV_CODEC_ID_THEORA, "Theora" },
    { 0, NULL }
};

static gfxoutputdrv_codec_t none_codeclist[] = {
    { AV_CODEC_ID_NONE, "" },
    { 0, NULL }
};


gfxoutputdrv_format_t ffmpegdrv_formatlist[] =
{
    { "avi", avi_audio_codeclist, avi_video_codeclist },
    { "mp4", mp4_audio_codeclist, mp4_video_codeclist },
    { "matroska", mp4_audio_codeclist, mp4_video_codeclist },
    { "ogg", ogg_audio_codeclist, ogg_video_codeclist },
    { "wav", NULL, NULL },
    { "mp3", NULL, none_codeclist },
    { "mp2", NULL, NULL },
    { NULL, NULL, NULL }
};

typedef struct OutputStream {
    AVStream *st;
    int64_t next_pts;
    int samples_count;
    AVFrame *frame;
    AVFrame *tmp_frame;

} OutputStream;

/* general */
static ffmpeglib_t ffmpeglib;
static AVFormatContext *ffmpegdrv_oc;
static AVOutputFormat *ffmpegdrv_fmt;
static int file_init_done;

/* audio */
static OutputStream audio_st = { 0 };
static AVCodec *avcodecaudio;
static soundmovie_buffer_t ffmpegdrv_audio_in;
static int audio_init_done;
static int audio_is_open;
static struct SwrContext *swr_ctx;
static int audio_outbuf_size;

/* video */
static OutputStream video_st = { 0 };
static AVCodec *avcodecvideo;
static int video_init_done;
static int video_is_open;
static int video_width, video_height;
static unsigned int framecounter;
#ifdef HAVE_FFMPEG_SWSCALE
static struct SwsContext *sws_ctx;
#endif

/* resources */
static char *ffmpeg_format = NULL;
static int format_index;
static int audio_bitrate;
static int video_bitrate;
static int audio_codec;
static int video_codec;
static int video_halve_framerate;

static int ffmpegdrv_init_file(void);

static int set_container_format(const char *val, void *param)
{
    int i;

    format_index = -1;
    for (i = 0; ffmpegdrv_formatlist[i].name != NULL; i++) {
        if (strcmp(val, ffmpegdrv_formatlist[i].name) == 0) {
            format_index = i;
        }
    }

    if (format_index < 0) {
        return -1;
    }

    util_string_set(&ffmpeg_format, val);

    return 0;
}

static int set_audio_bitrate(int val, void *param)
{
    audio_bitrate = (CLOCK)val;

    if ((audio_bitrate < VICE_FFMPEG_AUDIO_RATE_MIN)
        || (audio_bitrate > VICE_FFMPEG_AUDIO_RATE_MAX)) {
        audio_bitrate = VICE_FFMPEG_AUDIO_RATE_DEFAULT;
    }
    return 0;
}

static int set_video_bitrate(int val, void *param)
{
    video_bitrate = (CLOCK)val;

    if ((video_bitrate < VICE_FFMPEG_VIDEO_RATE_MIN)
        || (video_bitrate > VICE_FFMPEG_VIDEO_RATE_MAX)) {
        video_bitrate = VICE_FFMPEG_VIDEO_RATE_DEFAULT;
    }
    return 0;
}

static int set_audio_codec(int val, void *param)
{
    audio_codec = val;
    return 0;
}

static int set_video_codec(int val, void *param)
{
    video_codec = val;
    return 0;
}

static int set_video_halve_framerate(int value, void *param)
{
    int val = value ? 1 : 0;

    if (video_halve_framerate != val && screenshot_is_recording()) {
        ui_error("Can't change framerate while recording. Try again later.");
        return 0;
    }

    video_halve_framerate = val;

    return 0;
}

/*---------- Resources ------------------------------------------------*/

static const resource_string_t resources_string[] = {
    { "FFMPEGFormat", "avi", RES_EVENT_NO, NULL,
      &ffmpeg_format, set_container_format, NULL },
    { NULL }
};

static const resource_int_t resources_int[] = {
    { "FFMPEGAudioBitrate", VICE_FFMPEG_AUDIO_RATE_DEFAULT,
      RES_EVENT_NO, NULL,
      &audio_bitrate, set_audio_bitrate, NULL },
    { "FFMPEGVideoBitrate", VICE_FFMPEG_VIDEO_RATE_DEFAULT,
      RES_EVENT_NO, NULL,
      &video_bitrate, set_video_bitrate, NULL },
    { "FFMPEGAudioCodec", AV_CODEC_ID_MP3, RES_EVENT_NO, NULL,
      &audio_codec, set_audio_codec, NULL },
    { "FFMPEGVideoCodec", AV_CODEC_ID_MPEG4, RES_EVENT_NO, NULL,
      &video_codec, set_video_codec, NULL },
    { "FFMPEGVideoHalveFramerate", 0, RES_EVENT_NO, NULL,
      &video_halve_framerate, set_video_halve_framerate, NULL },
    { NULL }
};

static int ffmpegdrv_resources_init(void)
{
    if (resources_register_string(resources_string) < 0) {
        return -1;
    }

    return resources_register_int(resources_int);
}
/*---------------------------------------------------------------------*/


/*---------- Commandline options --------------------------------------*/

static const cmdline_option_t cmdline_options[] = {
    { "-ffmpegaudiobitrate", SET_RESOURCE, 1,
      NULL, NULL, "FFMPEGAudioBitrate", NULL,
      USE_PARAM_ID, USE_DESCRIPTION_ID,
      IDCLS_P_VALUE, IDCLS_SET_AUDIO_STREAM_BITRATE,
      NULL, NULL },
    { "-ffmpegvideobitrate", SET_RESOURCE, 1,
      NULL, NULL, "FFMPEGVideoBitrate", NULL,
      USE_PARAM_ID, USE_DESCRIPTION_ID,
      IDCLS_P_VALUE, IDCLS_SET_VIDEO_STREAM_BITRATE,
      NULL, NULL },
    { NULL }
};

static int ffmpegdrv_cmdline_options_init(void)
{
    return cmdline_register_options(cmdline_options);
}

/*---------------------------------------------------------------------*/
static int write_frame(AVFormatContext *fmt_ctx, const AVRational *time_base, AVStream *st, AVPacket *pkt)
{
    /* rescale output packet timestamp values from codec to stream timebase */
    (*ffmpeglib.p_av_packet_rescale_ts)(pkt, *time_base, st->time_base);
    pkt->stream_index = st->index;

    /* Write the compressed frame to the media file. */
    return (*ffmpeglib.p_av_interleaved_write_frame)(fmt_ctx, pkt);
}

static void close_stream(OutputStream *ost)
{
    (*ffmpeglib.p_avcodec_close)(ost->st->codec);
    (*ffmpeglib.p_av_frame_free)(&ost->frame);
    (*ffmpeglib.p_av_frame_free)(&ost->tmp_frame);
}


/*-----------------------*/
/* audio stream encoding */
/*-----------------------*/

static AVFrame *alloc_audio_frame(enum AVSampleFormat sample_fmt, 
    uint64_t channel_layout,
    int sample_rate, int nb_samples)
{
    AVFrame *frame = (*ffmpeglib.p_av_frame_alloc)();
    int ret;

    if (!frame) {
        log_debug("ffmpegdrv: Error allocating an audio frame");
        return NULL;
    }

    frame->format = sample_fmt;
    frame->channel_layout = channel_layout;
    frame->sample_rate = sample_rate;
    frame->nb_samples = nb_samples;

    if (nb_samples) {
        ret = (*ffmpeglib.p_av_frame_get_buffer)(frame, 0);
        if (ret < 0) {
            log_debug("ffmpegdrv: Error allocating an audio buffer");
            return NULL;
        }
    }

    return frame;
}


static int ffmpegdrv_open_audio(AVFormatContext *oc, AVStream *st)
{
    AVCodecContext *c;
    int audio_inbuf_samples;
    int ret;

    c = st->codec;
    /* open codec */
    ret = (*ffmpeglib.p_avcodec_open2)(c, avcodecaudio, NULL);
    if (ret < 0) {
        log_debug("ffmpegdrv: could not open audio codec (%d)", ret);
        return -1;
    }

    audio_is_open = 1;
    if (c->codec->capabilities & CODEC_CAP_VARIABLE_FRAME_SIZE) {
        audio_inbuf_samples = 10000;
    }
    else {
        audio_inbuf_samples = c->frame_size;
    }

    audio_st.frame = alloc_audio_frame(c->sample_fmt, c->channel_layout, c->sample_rate, audio_inbuf_samples);
    audio_st.tmp_frame = alloc_audio_frame(AV_SAMPLE_FMT_S16, c->channel_layout, c->sample_rate, audio_inbuf_samples);

    if (!audio_st.frame || !audio_st.tmp_frame) {
        return -1;
    }
    
    ffmpegdrv_audio_in.size = audio_inbuf_samples;
    ffmpegdrv_audio_in.buffer = (SWORD*)audio_st.tmp_frame->data[0];
    return 0;
}


static void ffmpegdrv_close_audio(void)
{
    if (audio_st.st == NULL) {
        return;
    }

    if (audio_is_open) {
        close_stream(&audio_st);
    }

    audio_is_open = 0;
    ffmpegdrv_audio_in.buffer = NULL;
    ffmpegdrv_audio_in.size = 0;
    (*ffmpeglib.p_swr_free)(&swr_ctx);

}


static int ffmpegmovie_init_audio(int speed, int channels, soundmovie_buffer_t ** audio_in)
{
    AVCodecContext *c;
    AVStream *st;
    int i;

    if (ffmpegdrv_oc == NULL || ffmpegdrv_fmt == NULL) {
        return -1;
    }

    audio_init_done = 1;

    if (ffmpegdrv_fmt->audio_codec == AV_CODEC_ID_NONE) {
        return -1;
    }

    *audio_in = &ffmpegdrv_audio_in;

    (*audio_in)->size = 0; /* not allocated yet */
    (*audio_in)->used = 0;

    st = (*ffmpeglib.p_avformat_new_stream)(ffmpegdrv_oc, avcodecaudio);
    if (!st) {
        log_debug("ffmpegdrv: Could not alloc audio stream");
        return -1;
    }
    
    c = st->codec;
    /* put sample parameters */
    c->sample_fmt = avcodecaudio->sample_fmts ? avcodecaudio->sample_fmts[0] : AV_SAMPLE_FMT_S16;
    c->bit_rate = audio_bitrate;
    c->sample_rate = speed;
    if (avcodecaudio->supported_samplerates) {
        c->sample_rate = avcodecaudio->supported_samplerates[0];
        for (i = 0; avcodecaudio->supported_samplerates[i]; i++) {
            if (avcodecaudio->supported_samplerates[i] == speed)
                c->sample_rate = speed;
        }
    }
    c->channel_layout = avcodecaudio->channel_layouts ? avcodecaudio->channel_layouts[0] : (channels == 1 ? AV_CH_LAYOUT_MONO : AV_CH_LAYOUT_STEREO);
    c->channels = (*ffmpeglib.p_av_get_channel_layout_nb_channels)(c->channel_layout);

    st->time_base = (AVRational){ 1, c->sample_rate };
    audio_st.st = st;
    audio_st.next_pts = 0;
    audio_st.samples_count = 0;

    /* Some formats want stream headers to be separate. */
    if (ffmpegdrv_oc->oformat->flags & AVFMT_GLOBALHEADER)
        c->flags |= CODEC_FLAG_GLOBAL_HEADER;

    /* create resampler context */
    swr_ctx = (*ffmpeglib.p_swr_alloc)();
    if (!swr_ctx) {
        log_debug("ffmpegdrv: Could not alloc resampler context");
        return -1;
    }

    /* set options */
    (*ffmpeglib.p_av_opt_set_int)(swr_ctx, "in_channel_count", c->channels, 0);
    (*ffmpeglib.p_av_opt_set_int)(swr_ctx, "in_sample_rate", speed, 0);
    (*ffmpeglib.p_av_opt_set_sample_fmt)(swr_ctx, "in_sample_fmt", AV_SAMPLE_FMT_S16, 0);
    (*ffmpeglib.p_av_opt_set_int)(swr_ctx, "out_channel_count", c->channels, 0);
    (*ffmpeglib.p_av_opt_set_int)(swr_ctx, "out_sample_rate", c->sample_rate, 0);
    (*ffmpeglib.p_av_opt_set_sample_fmt)(swr_ctx, "out_sample_fmt", c->sample_fmt, 0);

    /* initialize the resampling context */
    if ((*ffmpeglib.p_swr_init)(swr_ctx) < 0) {
        log_debug("ffmpegdrv: Failed to initialize the resampling context");
        return -1;
    }

    if (video_init_done) {
        ffmpegdrv_init_file();
    }

    return 0;
}


/* triggered by soundffmpegaudio->write */
static int ffmpegmovie_encode_audio(soundmovie_buffer_t *audio_in)
{
    int got_packet;
    int dst_nb_samples;
    AVPacket pkt = { 0 };
    AVCodecContext *c;
    AVFrame *frame;
    int ret;

    if (audio_st.st) {
        audio_st.frame->pts = audio_st.next_pts;
        audio_st.next_pts += audio_in->size;

        (*ffmpeglib.p_av_init_packet)(&pkt);
        c = audio_st.st->codec;

        frame = audio_st.tmp_frame;

        if (frame) {
            /* convert samples from native format to destination codec format, using the resampler */
            /* compute destination number of samples */
            dst_nb_samples = (int)(*ffmpeglib.p_av_rescale_rnd)((*ffmpeglib.p_swr_get_delay)(swr_ctx, c->sample_rate) + frame->nb_samples,
                c->sample_rate, c->sample_rate, AV_ROUND_UP);

            /* when we pass a frame to the encoder, it may keep a reference to it
            * internally;
            * make sure we do not overwrite it here
            */
            ret = (*ffmpeglib.p_av_frame_make_writable)(audio_st.frame);
            if (ret < 0)
                return -1;

            /* convert to destination format */
            ret = (*ffmpeglib.p_swr_convert)(swr_ctx,
                audio_st.frame->data, dst_nb_samples,
                (const uint8_t **)frame->data, frame->nb_samples);
            if (ret < 0) {
                log_debug("ffmpegdrv_encode_audio: Error while converting audio frame");
                return -1;
            }
            frame = audio_st.frame;
            frame->pts = (*ffmpeglib.p_av_rescale_q)(audio_st.samples_count, (AVRational){ 1, c->sample_rate }, c->time_base);
            audio_st.samples_count += dst_nb_samples;
        }


        ret = (*ffmpeglib.p_avcodec_encode_audio2)(audio_st.st->codec, &pkt, audio_st.frame, &got_packet);
        if (got_packet) {
            if (write_frame(ffmpegdrv_oc, &c->time_base, audio_st.st, &pkt)<0)
            {
                log_debug("ffmpegdrv_encode_audio: Error while writing audio frame");
            }
        }
    }

    audio_in->used = 0;
    return 0;
}

static void ffmpegmovie_close(void)
{
    /* just stop the whole recording */
    screenshot_stop_recording();
}

static soundmovie_funcs_t ffmpegdrv_soundmovie_funcs = {
    ffmpegmovie_init_audio,
    ffmpegmovie_encode_audio,
    ffmpegmovie_close
};

/*-----------------------*/
/* video stream encoding */
/*-----------------------*/
static int ffmpegdrv_fill_rgb_image(screenshot_t *screenshot, AVFrame *pic)
{
    int x, y;
    int colnum;
    int bufferoffset;
    int x_dim = screenshot->width;
    int y_dim = screenshot->height;
    int pix;

    /* center the screenshot in the video */
    bufferoffset = screenshot->x_offset
                   + screenshot->y_offset * screenshot->draw_buffer_line_size;

    pix = 3 * ((video_width - x_dim) / 2 + (video_height - y_dim) / 2 * video_width);

    for (y = 0; y < y_dim; y++) {
        for (x = 0; x < x_dim; x++) {
            colnum = screenshot->draw_buffer[bufferoffset + x];
            pic->data[0][pix++] = screenshot->palette->entries[colnum].red;
            pic->data[0][pix++] = screenshot->palette->entries[colnum].green;
            pic->data[0][pix++] = screenshot->palette->entries[colnum].blue;
        }
        pix += (3 * (video_width - x_dim));

        bufferoffset += screenshot->draw_buffer_line_size;
    }

    return 0;
}


static AVFrame* ffmpegdrv_alloc_picture(enum AVPixelFormat pix_fmt, int width, int height)
{
    AVFrame *picture;
    int ret;

    picture = (*ffmpeglib.p_av_frame_alloc)();
    if (!picture) {
        return NULL;
    }
    picture->format = pix_fmt;
    picture->width = width;
    picture->height = height;

    ret = (*ffmpeglib.p_av_frame_get_buffer)(picture, 32);
    if (ret < 0) {
        log_debug("ffmpegdrv: Could not allocate frame data");
        return NULL;
    }

    return picture;
}


static int ffmpegdrv_open_video(AVFormatContext *oc, AVStream *st)
{
    AVCodecContext *c;
    int ret;

    c = st->codec;

    /* open the codec */
    ret = (*ffmpeglib.p_avcodec_open2)(c, avcodecvideo, NULL);
    if (ret < 0) {
        log_debug("ffmpegdrv: could not open video codec");
        return -1;
    }

    video_is_open = 1;
    /* allocate the encoded raw picture */
    video_st.frame = ffmpegdrv_alloc_picture(c->pix_fmt, c->width, c->height);
    if (!video_st.frame) {
        log_debug("ffmpegdrv: could not allocate picture");
        return -1;
    }

    /* if the output format is not RGB24, then a temporary RGB24
       picture is needed too. It is then converted to the required
       output format */
    video_st.tmp_frame = NULL;
    if (c->pix_fmt != PIX_FMT_RGB24) {
        video_st.tmp_frame = ffmpegdrv_alloc_picture(PIX_FMT_RGB24, c->width, c->height);
        if (!video_st.tmp_frame) {
            log_debug("ffmpegdrv: could not allocate temporary picture");
            return -1;
        }
    }
    return 0;
}


static void ffmpegdrv_close_video(void)
{
    if (video_st.st == NULL) {
        return;
    }

    if (video_is_open) {
        close_stream(&video_st);
    }

    video_is_open = 0;

    if (video_st.frame) {
        lib_free(video_st.frame->data[0]);
        lib_free(video_st.frame);
        video_st.frame = NULL;
    }
    if (video_st.tmp_frame) {
        lib_free(video_st.tmp_frame->data[0]);
        lib_free(video_st.tmp_frame);
        video_st.tmp_frame = NULL;
    }

    if (sws_ctx != NULL) {
        (*ffmpeglib.p_sws_freeContext)(sws_ctx);
    }
}


static void ffmpegdrv_init_video(screenshot_t *screenshot)
{
    AVCodecContext *c;
    AVStream *st;

    if (ffmpegdrv_oc == NULL || ffmpegdrv_fmt == NULL) {
        return;
    }

    video_init_done = 1;

    if (ffmpegdrv_fmt->video_codec == AV_CODEC_ID_NONE) {
        return;
    }

    st = (*ffmpeglib.p_avformat_new_stream)(ffmpegdrv_oc, avcodecvideo);
    if (!st) {
        log_debug("ffmpegdrv: Could not alloc video stream\n");
        return;
    }

    c = st->codec;

    /* put sample parameters */
    c->bit_rate = video_bitrate;
    /* resolution should be a multiple of 16 */
    video_width = c->width = (screenshot->width + 15) & ~0xf;
    video_height = c->height = (screenshot->height + 15) & ~0xf;
    /* frames per second */
    st->time_base = (AVRational) {
        machine_get_cycles_per_frame(), (video_halve_framerate ? machine_get_cycles_per_second() / 2 : machine_get_cycles_per_second())
    };
    c->time_base = st->time_base;

    c->gop_size = 12; /* emit one intra frame every twelve frames at most */
    c->pix_fmt = AV_PIX_FMT_YUV420P;

    /* Avoid format conversion which would lead to loss of quality */
    if (c->codec_id == AV_CODEC_ID_FFV1) {
        c->pix_fmt = AV_PIX_FMT_0RGB32;
    }

    /* Use XVID instead of FMP4 FOURCC for better compatibility */
    if (c->codec_id == AV_CODEC_ID_MPEG4) {
        c->codec_tag = MKTAG('X', 'V', 'I', 'D');
    }

#ifdef HAVE_FFMPEG_SWSCALE
    /* setup scaler */
    if (c->pix_fmt != PIX_FMT_RGB24) {
        sws_ctx = (*ffmpeglib.p_sws_getContext)
                      (video_width, video_height, PIX_FMT_RGB24,
                      video_width, video_height, c->pix_fmt,
                      SWS_BICUBIC,
                      NULL, NULL, NULL);
        if (sws_ctx == NULL) {
            log_debug("ffmpegdrv: Can't create Scaler!\n");
        }
    }
#endif

    video_st.st = st;
    video_st.next_pts = 0;
    framecounter = 0;

    /* Some formats want stream headers to be separate. */
    if (ffmpegdrv_oc->oformat->flags & AVFMT_GLOBALHEADER)
        c->flags |= CODEC_FLAG_GLOBAL_HEADER;

    if (audio_init_done) {
        ffmpegdrv_init_file();
    }
}


static int ffmpegdrv_init_file(void)
{
    if (!video_init_done || !audio_init_done) {
        return 0;
    }

    (*ffmpeglib.p_av_dump_format)(ffmpegdrv_oc, 0, ffmpegdrv_oc->filename, 1);

    if (video_st.st && (ffmpegdrv_open_video(ffmpegdrv_oc, video_st.st) < 0)) {
        ui_error(translate_text(IDGS_FFMPEG_CANNOT_OPEN_VSTREAM));
        screenshot_stop_recording();
        return -1;
    }
    if (audio_st.st && (ffmpegdrv_open_audio(ffmpegdrv_oc, audio_st.st) < 0)) {
        ui_error(translate_text(IDGS_FFMPEG_CANNOT_OPEN_ASTREAM));
        screenshot_stop_recording();
        return -1;
    }

    if (!(ffmpegdrv_fmt->flags & AVFMT_NOFILE)) {
        if ((*ffmpeglib.p_avio_open)(&ffmpegdrv_oc->pb, ffmpegdrv_oc->filename,
                            AVIO_FLAG_WRITE) < 0) {

            ui_error(translate_text(IDGS_FFMPEG_CANNOT_OPEN_S), ffmpegdrv_oc->filename);
            screenshot_stop_recording();
            return -1;
        }
    }

    (*ffmpeglib.p_avformat_write_header)(ffmpegdrv_oc,NULL);

    log_debug("ffmpegdrv: Initialized file successfully");

    file_init_done = 1;

    return 0;
}


static int ffmpegdrv_save(screenshot_t *screenshot, const char *filename)
{
    gfxoutputdrv_format_t *format;

    video_st.st = NULL;
    audio_st.st = NULL;

    audio_init_done = 0;
    video_init_done = 0;
    file_init_done = 0;

    ffmpegdrv_fmt = (*ffmpeglib.p_av_guess_format)(ffmpeg_format, NULL, NULL);

    if (!ffmpegdrv_fmt) {
        ffmpegdrv_fmt = (*ffmpeglib.p_av_guess_format)("mpeg", NULL, NULL);
    }

    if (!ffmpegdrv_fmt) {
        log_debug("ffmpegdrv: Cannot find suitable output format");
        return -1;
    }

    if (format_index < 0) {
        return -1;
    }

    format = &ffmpegdrv_formatlist[format_index];

    if (format->audio_codecs != NULL) {
        /* the codec from resource */
        ffmpegdrv_fmt->audio_codec = audio_codec;
    }
    avcodecaudio = (*ffmpeglib.p_avcodec_find_encoder)(ffmpegdrv_fmt->audio_codec);

    if (format->video_codecs != NULL) {
        /* the codec from resource */
        ffmpegdrv_fmt->video_codec = video_codec;
    }
    avcodecvideo = (*ffmpeglib.p_avcodec_find_encoder)(ffmpegdrv_fmt->video_codec);

    ffmpegdrv_oc = (*ffmpeglib.p_avformat_alloc_context)();

    if (!ffmpegdrv_oc) {
        log_debug("ffmpegdrv: Cannot allocate format context");
        return -1;
    }

    ffmpegdrv_oc->oformat = ffmpegdrv_fmt;
    snprintf(ffmpegdrv_oc->filename, sizeof(ffmpegdrv_oc->filename), "%s", filename);

    ffmpegdrv_init_video(screenshot);

    soundmovie_start(&ffmpegdrv_soundmovie_funcs);

    return 0;
}


static int ffmpegdrv_close(screenshot_t *screenshot)
{
    unsigned int i;

    /* write the trailer, if any */
    if (file_init_done) {
        (*ffmpeglib.p_av_write_trailer)(ffmpegdrv_oc);
    }

    soundmovie_stop();

    if (video_st.st) {
        ffmpegdrv_close_video();
    }
    if (audio_st.st) {
        ffmpegdrv_close_audio();
    }

    if (!(ffmpegdrv_fmt->flags & AVFMT_NOFILE)) {
        /* close the output file */
            (*ffmpeglib.p_avio_close)(ffmpegdrv_oc->pb);
    }

    /* free the streams */
    for (i = 0; i < ffmpegdrv_oc->nb_streams; i++) {
        (*ffmpeglib.p_av_free)((void *)ffmpegdrv_oc->streams[i]);
        ffmpegdrv_oc->streams[i] = NULL;
    }

    /* free the stream */
    //lib_free(ffmpegdrv_oc);
    log_debug("ffmpegdrv: Closed successfully");

    file_init_done = 0;

    return 0;
}


/* triggered by screenshot_record */
static int ffmpegdrv_record(screenshot_t *screenshot)
{
    AVCodecContext *c;
    int ret;

    if (audio_init_done && video_init_done && !file_init_done) {
        ffmpegdrv_init_file();
    }

    if (video_st.st == NULL || !file_init_done) {
        return 0;
    }

    if (audio_st.st && video_st.next_pts > audio_st.next_pts) {
        /* drop this frame */
        return 0;
    }

    framecounter++;
    if (video_halve_framerate && (framecounter & 1)) {
        /* drop every second frame */
        return 0;
    }

    c = video_st.st->codec;

    if (c->pix_fmt != PIX_FMT_RGB24) {
        ffmpegdrv_fill_rgb_image(screenshot, video_st.tmp_frame);

        if (sws_ctx != NULL) {
            (*ffmpeglib.p_sws_scale)(sws_ctx,
                video_st.tmp_frame->data, video_st.tmp_frame->linesize, 0, c->height,
                video_st.frame->data, video_st.frame->linesize);
        }
    } else {
        ffmpegdrv_fill_rgb_image(screenshot, video_st.frame);
    }

    video_st.frame->pts = video_st.next_pts++;

    if (ffmpegdrv_oc->oformat->flags & AVFMT_RAWPICTURE) {
        AVPacket pkt;
        (*ffmpeglib.p_av_init_packet)(&pkt);
        pkt.flags |= AV_PKT_FLAG_KEY;
        pkt.stream_index = video_st.st->index;
        pkt.data = (uint8_t*)video_st.frame;
        pkt.size = sizeof(AVPicture);
        pkt.pts = pkt.dts = video_st.frame->pts;

        ret = (*ffmpeglib.p_av_interleaved_write_frame)(ffmpegdrv_oc, &pkt);
    } else {
        AVPacket pkt = { 0 };
        int got_packet;

        (*ffmpeglib.p_av_init_packet)(&pkt);

        /* encode the image */
        ret = (*ffmpeglib.p_avcodec_encode_video2)(c, &pkt, video_st.frame, &got_packet);
        if (ret < 0) {
            log_debug("Error while encoding video frame");
            return -1;
        }
        /* if zero size, it means the image was buffered */
        if (got_packet) {
            if (write_frame(ffmpegdrv_oc, &c->time_base, video_st.st, &pkt)<0)
            {
                log_debug("ffmpegdrv_encode_audio: Error while writing audio frame");
            }

        } else {
            ret = 0;
        }
    }
    if (ret < 0) {
        log_debug("Error while writing video frame");
        return -1;
    }

    return 0;
}


static int ffmpegdrv_write(screenshot_t *screenshot)
{
    return 0;
}

static void ffmpegdrv_shutdown(void)
{
    ffmpeglib_close(&ffmpeglib);
    lib_free(ffmpeg_format);
}

static gfxoutputdrv_t ffmpeg_drv = {
    "FFMPEG",
    "FFMPEG",
    NULL,
    ffmpegdrv_formatlist,
    NULL, /* open */
    ffmpegdrv_close,
    ffmpegdrv_write,
    ffmpegdrv_save,
    NULL,
    ffmpegdrv_record,
    ffmpegdrv_shutdown,
    ffmpegdrv_resources_init,
    ffmpegdrv_cmdline_options_init
#ifdef FEATURE_CPUMEMHISTORY
    , NULL
#endif
};

void gfxoutput_init_ffmpeg(void)
{
    if (ffmpeglib_open(&ffmpeglib) < 0) {
        return;
    }

    gfxoutput_register(&ffmpeg_drv);

    (*ffmpeglib.p_av_register_all)();
}

#endif
