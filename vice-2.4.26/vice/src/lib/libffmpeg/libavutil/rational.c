/*
 * rational numbers
 * Copyright (c) 2003 Michael Niedermayer <michaelni@gmx.at>
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
 * rational numbers
 * @author Michael Niedermayer <michaelni@gmx.at>
 */

#ifdef IDE_COMPILE
#include "libavutil/libm.h"
#endif

#include "avassert.h"
#include <limits.h>

#include "common.h"
#include "mathematics.h"
#include "rational.h"

int av_reduce(int *dst_num, int *dst_den,
              int64_t num, int64_t den, int64_t max)
{
    AVRational a0 = { 0, 1 }, a1 = { 1, 0 };
    int sign = (num < 0) ^ (den < 0);
    int64_t gcd = av_gcd(FFABS(num), FFABS(den));

    if (gcd) {
        num = FFABS(num) / gcd;
        den = FFABS(den) / gcd;
    }
    if (num <= max && den <= max) {
#ifdef IDE_COMPILE
		a1.num = num;
		a1.den = den;
#else
		a1 = (AVRational) { num, den };
#endif
		den = 0;
    }

    while (den) {
        uint64_t x        = num / den;
        int64_t next_den  = num - den * x;
        int64_t a2n       = x * a1.num + a0.num;
        int64_t a2d       = x * a1.den + a0.den;

        if (a2n > max || a2d > max) {
            if (a1.num) x =          (max - a0.num) / a1.num;
            if (a1.den) x = FFMIN(x, (max - a0.den) / a1.den);

            if (den * (2 * x * a1.den + a0.den) > num * a1.den) {
#ifdef IDE_COMPILE
				a1.num = x * a1.num + a0.num;
				a1.den = x * a1.den + a0.den;
#else
				a1 = (AVRational) { x * a1.num + a0.num, x * a1.den + a0.den };
#endif
			}
			break;
        }

        a0  = a1;
#ifdef IDE_COMPILE
		a1.num = a2n;
		a1.den = a2d;
#else
		a1  = (AVRational) { a2n, a2d };
#endif
		num = den;
        den = next_den;
    }
    av_assert2(av_gcd(a1.num, a1.den) <= 1U);

    *dst_num = sign ? -a1.num : a1.num;
    *dst_den = a1.den;

    return den == 0;
}

AVRational av_mul_q(AVRational b, AVRational c)
{
    av_reduce(&b.num, &b.den,
               b.num * (int64_t) c.num,
               b.den * (int64_t) c.den, INT_MAX);
    return b;
}

AVRational av_div_q(AVRational b, AVRational c)
{
#ifdef IDE_COMPILE
	AVRational tmp;
	
	tmp.num = c.den;
	tmp.den = c.num;
	return av_mul_q(b, tmp);
#else
	return av_mul_q(b, (AVRational) { c.den, c.num });
#endif
}

AVRational av_add_q(AVRational b, AVRational c) {
    av_reduce(&b.num, &b.den,
               b.num * (int64_t) c.den +
               c.num * (int64_t) b.den,
               b.den * (int64_t) c.den, INT_MAX);
    return b;
}

AVRational av_sub_q(AVRational b, AVRational c)
{
#ifdef IDE_COMPILE
	AVRational tmp;
	
	tmp.num = -c.num;
	tmp.den = c.den;
	return av_add_q(b, tmp);
#else
	return av_add_q(b, (AVRational) { -c.num, c.den });
#endif
}

AVRational av_d2q(double d, int max)
{
    AVRational a;
#define LOG2  0.69314718055994530941723212145817656807550013436025
    int exponent;
    int64_t den;
    if (isnan(d)) {
#ifdef IDE_COMPILE
		AVRational tmp = { 0,0 };
		return tmp;
#else
		return (AVRational) { 0,0 };
#endif
	}
	if (fabs(d) > INT_MAX + LLN(3)) {
#ifdef IDE_COMPILE
		AVRational tmp = { d < 0 ? -1 : 1, 0 };
		return tmp;
#else
		return (AVRational) { d < 0 ? -1 : 1, 0 };
#endif
	}
	exponent = FFMAX( (int)(log(fabs(d) + 1e-20)/LOG2), 0);
    den = LLN(1) << (61 - exponent);
    // (int64_t)rint() and llrint() do not work with gcc on ia64 and sparc64
    av_reduce(&a.num, &a.den, floor(d * den + 0.5), den, max);
    if ((!a.num || !a.den) && d && max>0 && max<INT_MAX)
        av_reduce(&a.num, &a.den, floor(d * den + 0.5), den, INT_MAX);

    return a;
}

int av_nearer_q(AVRational q, AVRational q1, AVRational q2)
{
    /* n/d is q, a/b is the median between q1 and q2 */
    int64_t a = q1.num * (int64_t)q2.den + q2.num * (int64_t)q1.den;
    int64_t b = 2 * (int64_t)q1.den * q2.den;

    /* rnd_up(a*d/b) > n => a*d/b > n */
    int64_t x_up = av_rescale_rnd(a, q.den, b, AV_ROUND_UP);

    /* rnd_down(a*d/b) < n => a*d/b < n */
    int64_t x_down = av_rescale_rnd(a, q.den, b, AV_ROUND_DOWN);

    return ((x_up > q.num) - (x_down < q.num)) * av_cmp_q(q2, q1);
}

int av_find_nearest_q_idx(AVRational q, const AVRational* q_list)
{
    int i, nearest_q_idx = 0;
    for (i = 0; q_list[i].den; i++)
        if (av_nearer_q(q, q_list[i], q_list[nearest_q_idx]) > 0)
            nearest_q_idx = i;

    return nearest_q_idx;
}

#ifdef TEST
int main(void)
{
    AVRational a,b,r;
    for (a.num = -2; a.num <= 2; a.num++) {
        for (a.den = -2; a.den <= 2; a.den++) {
            for (b.num = -2; b.num <= 2; b.num++) {
                for (b.den = -2; b.den <= 2; b.den++) {
                    int c = av_cmp_q(a,b);
                    double d = av_q2d(a) == av_q2d(b) ?
                               0 : (av_q2d(a) - av_q2d(b));
                    if (d > 0)       d = 1;
                    else if (d < 0)  d = -1;
                    else if (d != d) d = INT_MIN;
                    if (c != d)
                        av_log(NULL, AV_LOG_ERROR, "%d/%d %d/%d, %d %f\n", a.num,
                               a.den, b.num, b.den, c,d);
                    r = av_sub_q(av_add_q(b,a), b);
                    if(b.den && (r.num*a.den != a.num*r.den || !r.num != !a.num || !r.den != !a.den))
                        av_log(NULL, AV_LOG_ERROR, "%d/%d ", r.num, r.den);
                }
            }
        }
    }

    for (a.num = 1; a.num <= 10; a.num++) {
        for (a.den = 1; a.den <= 10; a.den++) {
            if (av_gcd(a.num, a.den) > 1)
                continue;
            for (b.num = 1; b.num <= 10; b.num++) {
                for (b.den = 1; b.den <= 10; b.den++) {
                    int start;
                    if (av_gcd(b.num, b.den) > 1)
                        continue;
                    if (av_cmp_q(b, a) < 0)
                        continue;
                    for (start = 0; start < 10 ; start++) {
                        int acc= start;
                        int i;

                        for (i = 0; i<100; i++) {
                            int exact = start + av_rescale_q(i+1, b, a);
                            acc = av_add_stable(a, acc, b, 1);
                            if (FFABS(acc - exact) > 2) {
                                av_log(NULL, AV_LOG_ERROR, "%d/%d %d/%d, %d %d\n", a.num,
                                       a.den, b.num, b.den, acc, exact);
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
#endif
