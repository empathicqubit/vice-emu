/*
 * viceglview.m - VICEGLView
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

#include <libkern/OSAtomic.h>

#include "lib.h"
#include "log.h"
#include "videoarch.h"
#include "vsync.h"

#import "viceglview.h"
#import "viceapplication.h"
#import "vicenotifications.h"

// import video log
extern log_t video_log;

//#define DEBUG_SYNC

@implementation VICEGLView

- (id)initWithFrame:(NSRect)frame
{
    // ----- OpenGL PixelFormat -----
    NSOpenGLPixelFormatAttribute attrs[] =
    {
        NSOpenGLPFAWindow,
        NSOpenGLPFANoRecovery,
        NSOpenGLPFAAccelerated,
        NSOpenGLPFADoubleBuffer,
        NSOpenGLPFAColorSize, (NSOpenGLPixelFormatAttribute)8,
//        NSOpenGLPFADepthSize, (NSOpenGLPixelFormatAttribute)16,
        (NSOpenGLPixelFormatAttribute)0
    };
    NSOpenGLPixelFormat * pf = [[NSOpenGLPixelFormat alloc] initWithAttributes:attrs];
    self = [super initWithFrame:frame
                    pixelFormat:pf];
    [pf release];
    if (self==nil)
        return nil;

    // ----- Drag & Drop -----
    [self registerForDraggedTypes:[NSArray arrayWithObject:NSFilenamesPboardType]];

    // ----- Mouse & Keyboard -----
    // setup keyboard
    lastKeyModifierFlags = 0;
    // setup mouse
    trackMouse = NO;
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(toggleMouse:)
                                                 name:VICEToggleMouseNotification
                                               object:nil];
    mouseHideTimer = nil;

    // ----- OpenGL -----
    // OpenGL locking and state
    glLock = [[NSRecursiveLock alloc] init];
    glContext = nil;
    isOpenGLReady = NO;
    postponedReconfigure = NO;
    
    // ----- DisplayLink -----
    displayLink = nil;
    displayLinkEnabled = NO;
    
    // ----- Multi Buffer -----
    machineRefreshPeriod = 0.0f;
    hostToMsFactor = 1000UL;
    displayDelta = 0;
    
    // ----- Pixel Buffer -----
    pixelBuffer = nil;
    glPixelBufferContext = nil;
    
    // ----- Texture -----
    [self initTextures];

    return self;
}

- (void)dealloc
{
    // ----- Pixel Buffer ----
    if(pixelBuffer != nil) {
        [self deletePixelBuffer];
    }
    
    // ----- DisplayLink -----
    if(displayLink != nil) {
        [self shutdownDisplayLink];
    }
    
    // ----- OpenGL -----
    [glLock lock];
    if([NSOpenGLContext currentContext] != glContext)
        [glContext makeCurrentContext];
    [self deleteAllTextures];
    [glLock unlock];    
    [glLock release];
    
    [super dealloc];
}

- (BOOL)isOpaque
{
    return YES;
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

// ---------- interface -----------------------------------------------------

// called on startup and every time video param changes
- (void)reconfigure:(struct video_param_s *)param
{
    // copy params
    if(param != NULL) {
        memcpy(&video_param, param, sizeof(struct video_param_s));
    }

    // if OpenGL is not initialized yet then postpone reconfigure
    if(!isOpenGLReady) {
        postponedReconfigure = YES;
        return;
    }
    
    log_message(video_log, "reconfiguring display");
    BOOL usePixelBuffer = NO;

    // do sync draw
    if(video_param.sync_draw_mode > SYNC_DRAW_OFF) {
        
        handleFullFrames = video_param.sync_draw_flicker_fix;
        
        // no blending only nearest frame
        int numDrawBuffers;
        if(video_param.sync_draw_mode == SYNC_DRAW_NEAREST) {
            if(handleFullFrames)
                numDrawBuffers = 2;
            else
                numDrawBuffers = 1;
            blendingEnabled = NO;
        }
        // blending
        else {
            numDrawBuffers = video_param.sync_draw_buffers;
            if(numDrawBuffers == 0) {
                if(handleFullFrames)
                    numDrawBuffers = 8;
                else
                    numDrawBuffers = 4;
            }
            blendingEnabled = YES;
            
            // flicker fixing needs a pixel buffer
            if(handleFullFrames) {
                handleFullFrames = [self setupPixelBufferWithSize:textureSize];
                usePixelBuffer = YES;
            } 
        }

        // limit max buffers
        if(numDrawBuffers > 16)
            numDrawBuffers = 16;
        
        // allocate textures
        [self setupTextures:numDrawBuffers withSize:textureSize];
        
        // enable display link
        if(displayLink == nil) {
            displayLinkSynced = NO;
            displayLinkEnabled = [self setupDisplayLink];
            log_message(video_log, "display link enabled: %s, blending: %s, flicker fixer: %s", 
                        (displayLinkEnabled ? "ok":"ERROR"),
                        (blendingEnabled ? "yes":"no"),
                        (handleFullFrames ? "yes":"no"));
        }
        
        // init blending
        [self initBlend];
    } 
    // no sync draw
    else {
        
        [self setupTextures:1 withSize:textureSize];
        
        blendingEnabled = NO;
        handleFullFrames = NO;
        
        // disable display link
        if(displayLink != nil) {
            [self shutdownDisplayLink];
            displayLinkEnabled = NO;
            log_message(video_log, "display link disabled");
        }

    }

    // init buffer setup
    numDrawn = 0;
    drawPos = 0;
    displayPos = blendingEnabled ? 1 : 0;
    firstDrawTime = 0;
    lastDrawTime = 0;
    lastDisplayTime = 0;
    blendAlpha = 1.0f;
    
    int i;
    for(i=0;i<MAX_BUFFERS;i++) {
        texture[i].timeStamp = 0;
    }
    
    // configure GL blending
    [self toggleBlending:blendingEnabled];
    
    // disable unused pixel buffer
    if(!usePixelBuffer) {
        [self deletePixelBuffer];
    }
}

// called if the canvas size was changed by the machine (not the user!)
- (void)resize:(NSSize)size
{
    // a resize might happen if the emulation video standard changes
    // so update the machine video parameters here
    float mrp = 1000.0f / (float)vsync_get_refresh_frequency();
    if(mrp != machineRefreshPeriod) {
        machineRefreshPeriod = mrp;
        log_message(video_log, "machine refresh period=%g ms", machineRefreshPeriod);

        if(blendingEnabled)
            [self initBlend];
    }

    // if OpenGL is not initialized then keep size and return
    if(!isOpenGLReady) {
        textureSize = size;
        return;
    }
    
    log_message(video_log, "resize canvas %g x %g", size.width, size.height);

    // re-adjust textures
    [self setupTextures:numTextures withSize:size];

    // re-adjust pixel buffer
    if(pixelBuffer != nil) {
        [self deletePixelBuffer];
        [self setupPixelBufferWithSize:size];
    }
}

// the emulation wants to draw a new frame (called from machine thread!)
- (BYTE *)beginMachineDraw:(int)frameNo
{
    unsigned long timeStamp = vsyncarch_gettime();

    // no drawing possible right now
    if(numTextures == 0) {
        log_message(video_log, "FATAL: no textures to draw...");
        return NULL;
    }
    
    // blend mode
    if(blendingEnabled) {

        // delta too small: frames arrive in < 1ms!
        // mainly needed on startup...
        if((timeStamp - lastDrawTime) < hostToMsFactor) {
#ifdef DEBUG_SYNC
            printf("COMPENSATE: #%d\n", drawPos);
#endif
            overwriteBuffer = YES;            
        }
        // no buffer free - need to overwrite the last one
        else if(numDrawn == numTextures) {
#ifdef DEBUG_SYNC
            printf("OVERWRITE: #%d\n", drawPos);
#endif
            overwriteBuffer = YES;
        } 
        // use next free buffer
        else {
            int oldPos = drawPos;
            overwriteBuffer = NO;
            drawPos++;
            if(drawPos == numTextures)
                drawPos = 0;
            
            // copy current image as base for next buffer (VICE does partial updates)
            memcpy(texture[drawPos].buffer, texture[oldPos].buffer, textureByteSize);      
        }
    }
    
    // store time stamp
    texture[drawPos].timeStamp = timeStamp;
    texture[drawPos].frameNo   = frameNo;
    lastDrawTime = timeStamp;
    if(firstDrawTime == 0) {
        firstDrawTime = timeStamp;
    }
    
    return texture[drawPos].buffer;
}

// the emulation did finish drawing a new frame (called from machine thread!)
- (void)endMachineDraw
{
    // update drawn texture
    [self updateTexture:drawPos];
    
    // blend draw
    if(blendingEnabled) {    
        // count written buffer
        if(!overwriteBuffer) {
            OSAtomicIncrement32(&numDrawn);
        }

#ifdef DEBUG_SYNC
        unsigned long ltime = 0;
        ltime = texture[drawPos].timeStamp - firstDrawTime;
        ltime /= hostToMsFactor;
        unsigned long ddelta = 0;
        if(numDrawn > 1) {
            int lastPos = (drawPos + numTextures - 1) % numTextures;
            ddelta = texture[drawPos].timeStamp - texture[lastPos].timeStamp;
            ddelta /= hostToMsFactor;
        }
        int frameNo = texture[drawPos].frameNo;
        printf("D %lu: +%lu @%d - draw #%d (total %d)\n", ltime, ddelta, frameNo, drawPos, numDrawn);
#endif
    }
    
    // if no display link then trigger redraw here
    if(!displayLinkEnabled) {
        [self setNeedsDisplay:YES];
    }
}

- (int)getCanvasPitch
{
    return textureSize.width * 4;
}

- (int)getCanvasDepth
{
    return 32;
}

- (void)setCanvasId:(int)c
{
    canvasId = c;
}

- (int)canvasId
{
    return canvasId;
}

// ---------- Cocoa Calls ---------------------------------------------------

- (void)commonGLSetup
{
    glDisable (GL_ALPHA_TEST);
    glDisable (GL_DEPTH_TEST);
    glDisable (GL_SCISSOR_TEST);
    glDisable (GL_DITHER);
    glDisable (GL_CULL_FACE);
    glColorMask (GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glDepthMask (GL_FALSE);
    glStencilMask (0);
    glClearColor (0.0f, 0.0f, 0.0f, 0.0f);
    glDisable (GL_BLEND);
    glHint (GL_TRANSFORM_HINT_APPLE, GL_FASTEST);

    glEnable(GL_TEXTURE_RECTANGLE_EXT);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE);    
}

// prepare open gl: called by view
- (void)prepareOpenGL
{
    [glLock lock];
    glContext = [self openGLContext];
    
    // sync to VBlank
    GLint swapInt = 1;
    [glContext setValues:&swapInt forParameter:NSOpenGLCPSwapInterval];
 
    [self commonGLSetup];
 
    [glLock unlock];
    
    isOpenGLReady = true;

    // call postponed configure
    if(postponedReconfigure) {
        [self reconfigure:NULL];
    }
}

- (void)toggleBlending:(BOOL)on
{
    [glLock lock];
    if([NSOpenGLContext currentContext] != glContext)
        [glContext makeCurrentContext];

    if(on)
        glEnable(GL_BLEND);
    else
        glDisable(GL_BLEND);
        
    [glLock unlock];
}

// cocoa calls this if view resized
- (void)reshape
{
    NSRect rect = [self bounds];
    NSSize size = rect.size;

    [glLock lock];
    if([NSOpenGLContext currentContext] != glContext)
        [glContext makeCurrentContext];
    
    // reshape viewport so that the texture size fits in without ratio distortion
    float ratio = size.width / size.height;
    float textureRatio = textureSize.width / textureSize.height;
    viewSize    = size;
    viewOrigin  = NSMakePoint(0.0,0.0);
    if (ratio < (textureRatio-0.01)) {
        // place along y
        viewSize.height = viewSize.width / textureRatio;
        viewOrigin.y = (size.height - viewSize.height) / 2.0; 
    } else if (ratio > (textureRatio+0.01)) {
        // place along x
        viewSize.width = viewSize.height * textureRatio;
        viewOrigin.x = (size.width - viewSize.width) / 2.0;
    }
    
    glViewport(viewOrigin.x, viewOrigin.y, viewSize.width, viewSize.height);
    
    // adjust mouse scales
    mouseXScale = textureSize.width  / viewSize.width;
    mouseYScale = textureSize.height / viewSize.height;

    [glLock unlock];
}

- (void)drawQuad:(float)alpha
{
    glBegin(GL_QUADS);
    {
        glColor4f(1.0f,1.0f,1.0f,alpha);
        glTexCoord2i(0, textureSize.height);          glVertex2i(-1, -1);
        glTexCoord2i(0, 0);                           glVertex2i(-1, 1);
        glTexCoord2i(textureSize.width, 0);           glVertex2i(1, 1);
        glTexCoord2i(textureSize.width, textureSize.height); glVertex2i(1, -1);
    }
    glEnd();
}

- (void)drawFlipQuad:(float)alpha
{
    glBegin(GL_QUADS);
    {
        glColor4f(1.0f,1.0f,1.0f,alpha);
        glTexCoord2i(0, 0);                           glVertex2i(-1, -1);
        glTexCoord2i(0, textureSize.height);          glVertex2i(-1, 1);
        glTexCoord2i(textureSize.width, textureSize.height); glVertex2i(1, 1);
        glTexCoord2i(textureSize.width, 0);           glVertex2i(1, -1);
    }
    glEnd();
}

// redraw view
- (void)drawRect:(NSRect)r
{
    [glLock lock];
    if([NSOpenGLContext currentContext] != glContext)
        [glContext makeCurrentContext];

    glClear(GL_COLOR_BUFFER_BIT);

    // anything to draw?
    if(numTextures > 0) {
        // multi buffer blends two textures
        if(blendingEnabled) {

            // calc blend position and determine weights
            int count = [self calcBlend];
            int pos = displayPos;
            
            // no blending
            if(count == 1) {
                glBlendFunc( GL_ONE, GL_ZERO );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:1.0f];
            }
            // blend two buffers (with blending)
            else if(count == 2) {
                glBlendFunc( GL_ONE, GL_ZERO );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:blendAlpha];
                
                pos++; if(pos == numTextures) pos = 0;
                float blendOneMinusAlpha = 1.0f - blendAlpha;
                
                glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:blendOneMinusAlpha];
            }
            // blend four buffers (2 x with blending into pixel buffer)
            else {
                // draw on pixel buffer
                [glPixelBufferContext makeCurrentContext];
                glClear(GL_COLOR_BUFFER_BIT);
                
                // frame l1
                glBlendFunc( GL_ONE, GL_ZERO );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:1.0f];
                pos++; if(pos == numTextures) pos = 0;

                // frame l2
                glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:0.5f];
                pos++; if(pos == numTextures) pos = 0;
                    
                glFlush();
                    
                // draw on main buffer
                [glContext makeCurrentContext];
                
                // frame r1
                glBlendFunc( GL_ONE, GL_ZERO );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:1.0f];
                pos++; if(pos == numTextures) pos = 0;

                // frame r2
                glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[pos].bindId);
                [self drawQuad:0.5f];
                pos++; if(pos == numTextures) pos = 0;
                                
                glBindTexture(GL_TEXTURE_RECTANGLE_EXT, pixelBufferTextureId);
                [glContext setTextureImageToPixelBuffer:pixelBuffer colorBuffer:GL_FRONT];
                [self drawFlipQuad:blendAlpha];
            }
        }
        // non-multi normal draw
        else {
            glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[0].bindId);
            [self drawQuad:1.0f];
        }
    }
    
    [[self openGLContext] flushBuffer];
    [glLock unlock];
}

// ---------- Multi Buffer Blending -----------------------------------------

- (void)initBlend
{
    float dd = 1.0f;
    if(handleFullFrames) {
        dd = 4.0f;
    }
    
    dd *= machineRefreshPeriod;
    log_message(video_log, "displayDelta: %g ms", dd);
    
    // the display delta for multi buffer is a machine refresh
    displayDelta = (unsigned long)((dd * (float)hostToMsFactor)+0.5f);
}

- (int)calcBlend
{
    // nothing to do yet
    if((firstDrawTime==0)||(displayDelta==0)) {
        return 1;
    }
    
    // convert now render time to frame time
    unsigned long now = vsyncarch_gettime();
    unsigned long frameNow = now - displayDelta;
    
    // find display frame interval where we fit in
    int np = displayPos;
    int nd = numDrawn;    
    int i = 0;

    for(i=0;i<nd;i++) {
        // next timestamp is larger -> keep i
        if(texture[np].timeStamp > frameNow)
            break;
        
        // next slot in ring buffer
        np++;
        if(np == numTextures)
            np = 0;            
    }
    
    // display is beyond or before current frame
    BOOL beyond = NO;
    BOOL before = NO;    
    if(i==0) {
        before = YES;
    } else {
        if(i == nd) {
            beyond = YES;
        }
        i--;
    }

    // the current display frame lies between machine frames [a;b]
    // at offset [aPos;bPos] = [i;i+1] to the last displayed frame
    int aOffset = i;
    int bOffset = i+1;
    int a = (displayPos + aOffset) % numTextures;
    int b = (displayPos + bOffset) % numTextures;
    
    // retrieve full frame for flicker fixing
    // we assume "full frame = even + odd frame" here
    BOOL leftFullFrame = NO;
    BOOL rightFullFrame = NO;
    int l1,l2; // left full frame [l1;l2]
    int r1,r2; // right full frame [r1;r2]
    if(handleFullFrames && !before && !beyond) {
        int aFrameNo = texture[a].frameNo;
        int bFrameNo = texture[b].frameNo;
        int aEven = (aFrameNo & 1) == 0;
    
        // make sure a and b are consecutive frames
        // (this is the essential prerequisite for flicker fixing)
        if((aFrameNo + 1) == bFrameNo) {
            // potential begin of a right full frame
            int r1Pos;
            int r1FrameNo;
            int r1Offset;
            
            // F=[a;b] is a full frame
            if(aEven) {
                leftFullFrame = YES;
                l1 = a;
                l2 = b;
                
                // possible right full frame start
                r1        = (b + 1) % numTextures;
                r1Offset  = bOffset + 1;
                r1FrameNo = texture[r1].frameNo;
            }
            // F=[c=a-1;a] could be a full frame
            else if(i>0) {
                l1 = (displayPos + i - 1) % numTextures;
                int l1FrameNo = texture[l1].frameNo;
                if((l1FrameNo + 1) == aFrameNo) {
                    leftFullFrame = YES;
                    l2 = a;
                    i--; // keep l1!
                    
                    // possible right full frame start
                    r1        = b;
                    r1Offset  = bOffset;
                    r1FrameNo = bFrameNo;
                }
            }

            // a left full frame was found
            if(leftFullFrame == YES) {
                int r2Offset = r1Offset + 1;
                // we have enough frames for a second full frame
                if(r2Offset < nd) {
                    r2 = (r1 + 1) % numTextures;
                    int r2FrameNo = texture[r2].frameNo;
                    if((r1FrameNo + 1) == r2FrameNo) {
                        rightFullFrame = YES;
                    }
                }
            }
        }
    }

#ifdef DEBUG_SYNC
    unsigned long ltime = 0;
    if(frameNow > firstDrawTime)
        ltime = frameNow - firstDrawTime;
    unsigned long ddelta = ltime - lastDisplayTime;
    lastDisplayTime = ltime;
    ltime /= hostToMsFactor;
    ddelta /= hostToMsFactor;
    int oldDisplayPos = displayPos;
#endif

    // skip now unused frames... make room for drawing
    // and set new display pos
    if(i>0) {
        OSAtomicAdd32(-i, &numDrawn);
        displayPos = (displayPos + i) % numTextures;
    }

    // number of blended frames
    int count;
    
    // before first frame
    if(before) {
        count = 1;
#ifdef DEBUG_SYNC
        unsigned long delta = texture[displayPos].timeStamp - frameNow; 
        delta /= hostToMsFactor;
        printf("R %lu: +%lu BEFORE: #%d delta=%lu skip=%d\n", ltime, ddelta, displayPos, delta, i);
#endif
    }
    // beyond last frame
    else if(beyond) {
        count = 1;
#ifdef DEBUG_SYNC
        unsigned long delta = frameNow - texture[displayPos].timeStamp;  
        delta /= hostToMsFactor;
        printf("R %lu: +%lu BEYOND: #%d delta=%lu skip=%d\n", ltime, ddelta, displayPos, delta, i);
#endif
    } 
    // FF: inside full frame but no right frame
    else if(leftFullFrame) {
        if(rightFullFrame) {
            unsigned long frameDelta = texture[r1].timeStamp - texture[l1].timeStamp;
            unsigned long dispDelta  = texture[r1].timeStamp - frameNow;
            blendAlpha = (float)dispDelta / (float)frameDelta;
#ifdef DEBUG_SYNC
            printf("R %lu: +%lu TWO FF: #%d [%d,%d=-%lu ; %d,%d=%lu] oldpos=%d skip=%d avail=%d -> alpha=%g\n", 
                   ltime, ddelta, 
                   displayPos,
                   l1, l2, (frameNow - texture[l1].timeStamp) / hostToMsFactor,
                   r1, r2, (texture[r1].timeStamp - frameNow) / hostToMsFactor,
                   oldDisplayPos, i, nd,
                   blendAlpha);
#endif
            
            count = 4;
        } else {
            blendAlpha = 0.5f;
            count = 2;
#ifdef DEBUG_SYNC
            unsigned long delta = frameNow - texture[l1].timeStamp;  
            delta /= hostToMsFactor;
            printf("R %lu: +%lu ONE FF: #%d [%d,%d=-%lu] oldpos=%d skip=%d avail=%d\n",
                   ltime, ddelta,
                   displayPos, 
                   l1, l2, delta,
                   oldDisplayPos, i, nd);
#endif        
        }
    }
    // between two frames (or between to FF/HF in flicker fixer)
    else {
        unsigned long frameDelta = texture[b].timeStamp - texture[a].timeStamp;
        unsigned long dispDelta  = texture[b].timeStamp - frameNow;
        blendAlpha = (float)dispDelta / (float)frameDelta;
        count = 2;
#ifdef DEBUG_SYNC
        printf("R %lu: +%lu between: #%d [%d=-%lu ; %d=%lu] skip=%d -> alpha=%g\n", 
               ltime, ddelta, 
               displayPos,
               a, frameNow - texture[a].timeStamp,
               b, texture[b].timeStamp - frameNow,
               i,
               blendAlpha);
#endif
    }
        
    return count;
}

// ---------- Pixel Buffer --------------------------------------------------

- (BOOL)setupPixelBufferWithSize:(NSSize)size
{
    // already allocated
    if((pixelBuffer != nil) && (glPixelBufferContext != nil))
        return YES;
    
    //Create the OpenGL pixel buffer to render into
    pixelBuffer = [[NSOpenGLPixelBuffer alloc] initWithTextureTarget:GL_TEXTURE_RECTANGLE_EXT 
        textureInternalFormat:GL_RGBA 
        textureMaxMipMapLevel:0 
        pixelsWide:size.width 
        pixelsHigh:size.height];
    if(pixelBuffer == nil) {
        log_message(video_log, "ERROR creating pixel buffer of size %g x %g!", size.width, size.height);
        return NO;
    }
        
    NSOpenGLPixelFormatAttribute attrs[] =
    {
        NSOpenGLPFAPixelBuffer,
        NSOpenGLPFANoRecovery,
        NSOpenGLPFAAccelerated,
        NSOpenGLPFAColorSize, (NSOpenGLPixelFormatAttribute)8,
        (NSOpenGLPixelFormatAttribute) 0
    };
    NSOpenGLPixelFormat * pf = [[NSOpenGLPixelFormat alloc] initWithAttributes:attrs];

    //Create the OpenGL context to render with (with color and depth buffers)
    glPixelBufferContext = [[NSOpenGLContext alloc] initWithFormat:pf shareContext:glContext];
    [pf release];
    if(glPixelBufferContext == nil) {
        log_message(video_log, "ERROR creating pixel buffer context!");
        return NO;
    }
    
    [glPixelBufferContext setPixelBuffer:pixelBuffer 
                             cubeMapFace:0
                             mipMapLevel:0
                    currentVirtualScreen:[glPixelBufferContext currentVirtualScreen]];
    
    log_message(video_log, "created pixel buffer of size %g x %g", 
                size.width, size.height);
                
    // init pixel buffer
    [glLock lock];
    if([NSOpenGLContext currentContext] != glPixelBufferContext)
        [glPixelBufferContext makeCurrentContext];
    
    glViewport(0,0,size.width,size.height);
    [self commonGLSetup];
    glEnable(GL_BLEND);
    
    // configure texture in main context to attach the pixel buffer to
    [glContext makeCurrentContext];
    glGenTextures(1,&pixelBufferTextureId);
    glBindTexture(GL_TEXTURE_RECTANGLE_EXT, pixelBufferTextureId);
    
    glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_WRAP_S, GL_CLAMP);
    glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_WRAP_T, GL_CLAMP);    

    glTexEnvi(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_ENV_MODE, GL_DECAL);
    
    [glLock unlock];
                
    return YES;
}

- (void)deletePixelBuffer
{
    BOOL done = NO;
    if(glPixelBufferContext != nil) {
        [glPixelBufferContext clearDrawable];
        [glPixelBufferContext release];
        glPixelBufferContext = nil;
        done = YES;
    }
    
    //Destroy the OpenGL pixel buffer
    if(pixelBuffer != nil) {
        [pixelBuffer release];
        pixelBuffer = nil;
        done = YES;
    }
    
    glDeleteTextures(1, &pixelBufferTextureId);
    
    if(done)
        log_message(video_log, "deleted pixel buffer");
}

// ---------- Texture Management --------------------------------------------

- (void)initTextures
{
    int i;
    
    numTextures = 0;
    for(i=0;i<MAX_BUFFERS;i++) {
        texture[i].buffer = NULL;
    }
}

- (void)deleteTexture:(int)tid
{
    lib_free(texture[tid].buffer);
    texture[tid].buffer = NULL;
    
    glDeleteTextures(1,&texture[tid].bindId);
}

- (void)deleteAllTextures
{
    int i;
    for(i=0;i<numTextures;i++) {
        [self deleteTexture:i];
    }
    numTextures = 0;
}

- (void)setupTextures:(int)num withSize:(NSSize)size
{
    int i;
    
    log_message(video_log, "setup textures: #%d %g x %g (was: #%d %g x %g)", 
                num, size.width, size.height, 
                numTextures, textureSize.width, textureSize.height);

    // clean up old textures
    if(numTextures > num) {
        [glLock lock];
        if([NSOpenGLContext currentContext] != glContext)
            [glContext makeCurrentContext];

        for(i=num;i<numTextures;i++) {
            [self deleteTexture:i];
        }
        [glLock unlock];
    }
    
    // if size differs then reallocate all otherwise only missing
    int start;
    if((size.width != textureSize.width)||(size.height != textureSize.height)) {
        start = 0;
    } else {
        start = numTextures;
    }
    
    // now adopt values
    textureSize = size;
    numTextures = num;    
    textureByteSize = size.width * size.height * 4;

    // setup texture memory
    for(i=start;i<numTextures;i++) {
        if (texture[i].buffer==NULL)
            texture[i].buffer = lib_malloc(textureByteSize);
        else
            texture[i].buffer = lib_realloc(texture[i].buffer, textureByteSize);
    
        // memory error
        if(texture[i].buffer == NULL) {
            numTextures = i;
            return;
        }
    
        // clear new texture - make sure alpha is set
        memset(texture[i].buffer, 0, textureByteSize);
    }
    
    // make GL context current
    [glLock lock];
    if([NSOpenGLContext currentContext] != glContext)
        [glContext makeCurrentContext];

    // bind textures and initialize them
    for(i=start;i<numTextures;i++) {
        glGenTextures(1, &texture[i].bindId);
        glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[i].bindId);
        BYTE *data = texture[i].buffer;
        
        glTextureRangeAPPLE(GL_TEXTURE_RECTANGLE_EXT, textureByteSize, data);
        glPixelStorei(GL_UNPACK_CLIENT_STORAGE_APPLE, GL_TRUE);
        glTexParameteri(GL_TEXTURE_RECTANGLE_EXT,
                        GL_TEXTURE_STORAGE_HINT_APPLE, GL_STORAGE_SHARED_APPLE);

        glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_WRAP_S, GL_CLAMP);
        glTexParameteri(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_WRAP_T, GL_CLAMP);    

        glTexEnvi(GL_TEXTURE_RECTANGLE_EXT, GL_TEXTURE_ENV_MODE, GL_DECAL);

        glTexImage2D(GL_TEXTURE_RECTANGLE_EXT, 0, GL_RGBA,
                     textureSize.width, textureSize.height,
                     0, 
                     GL_BGRA, GL_UNSIGNED_INT_8_8_8_8_REV, 
                     data);
    }

    [glLock unlock];
}

- (void)updateTexture:(int)i
{
    [glLock lock];
    if([NSOpenGLContext currentContext] != glContext)
        [glContext makeCurrentContext];

    glBindTexture(GL_TEXTURE_RECTANGLE_EXT, texture[i].bindId);
    glTexImage2D(GL_TEXTURE_RECTANGLE_EXT, 0, GL_RGBA,
                 textureSize.width, textureSize.height,
                 0, 
                 GL_BGRA, GL_UNSIGNED_INT_8_8_8_8_REV, 
                 texture[i].buffer);

    [glLock unlock];
}

// ----- Drag & Drop -----

- (NSDragOperation)draggingEntered:(id <NSDraggingInfo>)sender
{
    if (NSDragOperationGeneric & [sender draggingSourceOperationMask])
        return NSDragOperationLink;
    else
        return NSDragOperationNone;
}

- (BOOL)performDragOperation:(id <NSDraggingInfo>)sender
{
    id files = [[sender draggingPasteboard] propertyListForType:NSFilenamesPboardType];
    NSString * path = [files objectAtIndex:0];
    return [[VICEApplication theMachineController] smartAttachImage:path withProgNum:0 andRun:YES];
}

// ----- Keyboard -----

- (void)keyUp:(NSEvent *)theEvent
{
    unsigned int code = [theEvent keyCode];
    [[VICEApplication theMachineController] keyReleased:code];
}

- (void)flagsChanged:(NSEvent *)theEvent
{
    unsigned int modifierFlags = [theEvent modifierFlags] &
        (NSAlphaShiftKeyMask | NSShiftKeyMask | NSControlKeyMask | NSAlternateKeyMask);

    if (modifierFlags != lastKeyModifierFlags) {
        unsigned int code = [theEvent keyCode];
        unsigned int changedFlags = modifierFlags ^ lastKeyModifierFlags;
        int i;
        for (i=0;i<NUM_KEY_MODIFIERS;i++) {
            unsigned int flag = 1<<i;
            if (changedFlags & flag) {
                modifierKeyCode[i] = code;
                if (modifierFlags & flag) {
                    [[VICEApplication theMachineController] keyPressed:code];
                } else {
                    [[VICEApplication theMachineController] keyReleased:code];
                }
            }
        }
        lastKeyModifierFlags = modifierFlags;
    }
}


- (void)keyDown:(NSEvent *)theEvent
{
    unsigned int modifierFlags = [theEvent modifierFlags] &
        (NSAlphaShiftKeyMask | NSShiftKeyMask | NSControlKeyMask | NSAlternateKeyMask);

    // modifiers have changed, too!
    /* this happens if e.g. a context menu was activated by Ctrl-click */
    if (modifierFlags != lastKeyModifierFlags) {
        unsigned int changedFlags = modifierFlags ^ lastKeyModifierFlags;
        int i;
        for (i=0;i<NUM_KEY_MODIFIERS;i++) {
            unsigned int flag = 1<<i;
            if (changedFlags & flag) {
                unsigned int code = modifierKeyCode[i];
                if (modifierFlags & flag) {
                    [[VICEApplication theMachineController] keyPressed:code];
                } else {
                    [[VICEApplication theMachineController] keyReleased:code];
                }
            }
        }
        lastKeyModifierFlags = modifierFlags;
    }

    if (![theEvent isARepeat] &&
        !([theEvent modifierFlags] & NSCommandKeyMask)) {
        unsigned int code = [theEvent keyCode];
        [[VICEApplication theMachineController] keyPressed:code];
    }
}

// ----- Mouse -----

- (void)startHideTimer
{
    if (mouseHideTimer==nil) {
        // setup timer for mouse hide
        mouseHideInterval = MOUSE_HIDE_DELAY;
        mouseHideTimer = [NSTimer scheduledTimerWithTimeInterval: 0.5
                                                          target: self 
                                                        selector: @selector(hideTimer:)
                                                        userInfo: nil 
                                                         repeats: YES];
        [mouseHideTimer fire];
        [mouseHideTimer retain];
    }
}

- (void)stopHideTimer:(BOOL)shown
{
    if (mouseHideTimer!=nil) {
        // remove timer
        [mouseHideTimer invalidate];
        [mouseHideTimer release];
        mouseHideTimer = nil;
    }
    
    if (shown) {
        if (mouseHideInterval != MOUSE_IS_SHOWN) {
            [NSCursor setHiddenUntilMouseMoves:NO];
            mouseHideInterval = MOUSE_IS_SHOWN;
        }
    } else {
        if (mouseHideInterval != MOUSE_IS_HIDDEN) {
            [NSCursor setHiddenUntilMouseMoves:YES];
            mouseHideInterval = MOUSE_IS_HIDDEN;
        }
    }
}

- (void)hideTimer:(NSTimer *)timer
{
    if (mouseHideInterval>0) {
        mouseHideInterval--;
    } else if (mouseHideInterval==0) {
        [self stopHideTimer:FALSE];
    }
}

- (void)ensureMouseShown
{
    // in mouse tracking the mouse is always visible
    if (trackMouse)
        return;
    
    // reshow mouse if it was hidden
    if (mouseHideInterval == MOUSE_IS_HIDDEN) {
        [NSCursor setHiddenUntilMouseMoves:NO];
    }
    mouseHideInterval = MOUSE_HIDE_DELAY;
    [self startHideTimer];
}

- (BOOL)becomeFirstResponder
{
    [[self window] setAcceptsMouseMovedEvents:YES];
    
    // report current canvas id to app controller
    [VICEApplication setCurrentCanvasId:canvasId];
    
    // start mouse hide timer
    if (!trackMouse) {
        [self startHideTimer];
    }

    return [super becomeFirstResponder];
}

- (BOOL)resignFirstResponder
{
    [[self window] setAcceptsMouseMovedEvents:NO];
    
    // show mouse again
    if (!trackMouse) {
        [self stopHideTimer:TRUE];
    }

    return [super resignFirstResponder];
}

- (void)mouseMoved:(NSEvent *)theEvent
{
    NSPoint location = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    [self mouseMove:location];
    
    // check if mouse is in view
    BOOL inView = NSPointInRect(location,[self bounds]);
    if (inView) {
        [self ensureMouseShown];        
    } else {
        [self stopHideTimer:TRUE];
    }
}

- (void)mouseDragged:(NSEvent *)theEvent
{
    NSPoint location = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    [self mouseMove:location];
}

- (void)mouseMove:(NSPoint)pos
{
    if (trackMouse) {
        int w = (int)textureSize.width;
        int h = (int)textureSize.height;
        int px = (int)((pos.x-viewOrigin.x) * mouseXScale);
        int py = (int)((pos.y-viewOrigin.y) * mouseYScale);
        py = h - 1 - py;
        if ((px>=0)&&(px<w)&&(py>=0)&&(py<h)) {
            [[VICEApplication theMachineController] mouseMoveToX:px andY:py];
        }
    }
}

- (void)mouseDown:(NSEvent *)theEvent
{
    if ([theEvent type]==NSLeftMouseDown) {
        if (trackMouse) {
            [[VICEApplication theMachineController] mousePressed];
        } else {
            [self stopHideTimer:TRUE];
        }
    }
}

- (void)mouseUp:(NSEvent *)theEvent
{
    if ([theEvent type]==NSLeftMouseUp) {
        if (trackMouse) {
            [[VICEApplication theMachineController] mouseReleased];
        } else {
            [self startHideTimer];
        }
    }
}

- (void)toggleMouse:(NSNotification *)notification
{
    NSDictionary *dict = [notification userInfo];
    trackMouse = [[dict objectForKey:@"mouse"] boolValue];

    if (trackMouse) {
        [self stopHideTimer:TRUE];
    } else {
        [self startHideTimer];
    }
}

// ---------- display link stuff --------------------------------------------

- (CVReturn)displayLinkCallback
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    
    // not synced yet?
    if(!displayLinkSynced) {
        screenRefreshPeriod = [self getDisplayLinkRefreshPeriod];
        if(screenRefreshPeriod != 0.0) {
            displayLinkSynced = YES;
            float rate = 1000.0f / screenRefreshPeriod;
            log_message(video_log, "locked to screen refresh period=%g ms, rate=%g Hz",
                        screenRefreshPeriod, rate);
        }
    }
    
    // do drawing
    [self drawRect:NSZeroRect];
           
    [pool release];
    
    return kCVReturnSuccess;
}

static CVReturn MyDisplayLinkCallback(CVDisplayLinkRef displayLink, 
                                      const CVTimeStamp* nowTime,
                                      const CVTimeStamp* outputTime, 
                                      CVOptionFlags flagsIn,
                                      CVOptionFlags* flagsOut,
                                      void* displayLinkContext)
{
    VICEGLView *view = (VICEGLView *)displayLinkContext;
    CVReturn result = [view displayLinkCallback];
    return result;
}

- (BOOL)setupDisplayLink
{        
    CVReturn r;
    
    // Create a display link capable of being used with all active displays
    r = CVDisplayLinkCreateWithActiveCGDisplays(&displayLink);
    if( r != kCVReturnSuccess )
        return NO;

    // Set the renderer output callback function
    r = CVDisplayLinkSetOutputCallback(displayLink, &MyDisplayLinkCallback, self);
    if( r != kCVReturnSuccess )
        return NO;

    // Set the display link for the current renderer
    CGLContextObj cglContext = [[self openGLContext] CGLContextObj];
    CGLPixelFormatObj cglPixelFormat = [[self pixelFormat] CGLPixelFormatObj];
    r = CVDisplayLinkSetCurrentCGDisplayFromOpenGLContext(displayLink, cglContext, cglPixelFormat);
    if( r != kCVReturnSuccess )
        return NO;

    // Activate the display link
    r = CVDisplayLinkStart(displayLink);
    if( r != kCVReturnSuccess )
        return NO;
    
    return YES;
}

- (void)shutdownDisplayLink
{
    // Release the display link
    CVDisplayLinkRelease(displayLink);
    displayLink = NULL;
}

- (float)getDisplayLinkRefreshPeriod
{
    // return output video rate
    if(displayLink != nil) {
        // in ms!
        return (float)(CVDisplayLinkGetActualOutputVideoRefreshPeriod(displayLink) * 1000.0f);
    } else {
        return 0.0;
    }
}

@end
