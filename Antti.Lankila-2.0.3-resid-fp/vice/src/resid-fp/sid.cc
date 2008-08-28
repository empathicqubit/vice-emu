//  ---------------------------------------------------------------------------
//  This file is part of reSID, a MOS6581 SID emulator engine.
//  Copyright (C) 2004  Dag Lem <resid@nimrod.no>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//  ---------------------------------------------------------------------------

#include "sid.h"

#include <math.h>

#ifdef __SSE__
#include <xmmintrin.h>
#endif

#ifdef __SSE__
struct cpu_x86_regs_s {
  unsigned int eax;
  unsigned int ebx;
  unsigned int ecx;
  unsigned int edx;
};
typedef struct cpu_x86_regs_s cpu_x86_regs_t;

static cpu_x86_regs_t get_cpu_regs(unsigned int index)
{
  cpu_x86_regs_t retval;

  asm("movl %4, %%eax; cpuid; movl %%eax, %0; movl %%ebx, %1; movl %%ecx, %2; movl %%edx, %3;"
      : "=m" (retval.eax),
        "=m" (retval.ebx),
        "=m" (retval.ecx),
        "=m" (retval.edx)
      : "r"  (index)
      : "eax", "ebx", "ecx", "edx");

    return retval;
}

int detect_sse_done = 0;
int detect_sse_result = 0;

static int detect_sse(void)
{
#ifdef __x86_64__
  return 1;
#else
  unsigned long temp1, temp2;
  cpu_x86_regs_t cpu_id_return;
  unsigned int cpu_type, cpu_level;

  if (detect_sse_done == 1)
  {
    return detect_sse_result;
  }
  else
  {

    /* see if we are dealing with a cpu that has the cpuid instruction */
    asm("pushfl; popl %%eax; movl %%eax, %0; xorl $0x200000, %%eax; pushl %%eax; popfl; pushfl; popl %%eax; movl %%eax, %1; pushl %0; popfl "
        : "=r" (temp1),
        "=r" (temp2)
        :
        : "eax");
    
    temp1 &= 0x200000;
    temp2 &= 0x200000;
    if (temp1 == temp2)
    {
      /* no cpuid support, so return 0 */
      detect_sse_done = 1;
      return 0;
    }

    /* get max levels and type of cpu */
    cpu_id_return = get_cpu_regs(0);

    cpu_level = cpu_id_return.eax;
    if (cpu_level == 0)
    {
      /* no more levels, so no sse, return 0 */
      detect_sse_done = 1;
      return 0;
    }

    cpu_type = cpu_id_return.ebx;
    if (cpu_type != 0x756e6547)
    {
      /* cpu type is not intel, so return 0 */
      detect_sse_done = 1;
      return 0;
    }

    cpu_id_return = get_cpu_regs(1);

    if (cpu_id_return.edx & (1<<25))
    {
      detect_sse_result = 1;
    }
    detect_sse_done = 1;

    return detect_sse_result;
  }
#endif
}
#endif

float SIDFP::kinked_dac(const int x, const float nonlinearity, const int max)
{
    float value = 0.f;
    
    int bit = 1;
    float weight = 1.f;
    const float dir = 2.0f * nonlinearity;
    for (int i = 0; i < max; i ++) {
        if (x & bit)
            value += weight;
        bit <<= 1;
        weight *= dir;
    }

    return value / (weight / nonlinearity) * (1 << max);
}

// ----------------------------------------------------------------------------
// Constructor.
// ----------------------------------------------------------------------------
SIDFP::SIDFP()
{
  // Initialize pointers.
  sample = 0;
  fir = 0;

  voice[0].set_sync_source(&voice[2]);
  voice[1].set_sync_source(&voice[0]);
  voice[2].set_sync_source(&voice[1]);

  set_sampling_parameters(985248, SAMPLE_INTERPOLATE, 44100);

  bus_value = 0;
  bus_value_ttl = 0;

  input(0);
}


// ----------------------------------------------------------------------------
// Destructor.
// ----------------------------------------------------------------------------
SIDFP::~SIDFP()
{
  delete[] sample;
  delete[] fir;
}


// ----------------------------------------------------------------------------
// Set chip model.
// ----------------------------------------------------------------------------
void SIDFP::set_chip_model(chip_model model)
{
  for (int i = 0; i < 3; i++) {
    voice[i].set_chip_model(model);
  }

  filter.set_chip_model(model);
  extfilt.set_chip_model(model);
}

/* nonlinear DAC support, set 1 for 8580 / no effect, about 0.96 otherwise */
void SIDFP::set_voice_nonlinearity(float nl)
{
  for (int i = 0; i < 3; i++) {
    voice[i].set_nonlinearity(nl);
  }
}

// ----------------------------------------------------------------------------
// SID reset.
// ----------------------------------------------------------------------------
void SIDFP::reset()
{
  for (int i = 0; i < 3; i++) {
    voice[i].reset();
  }
  filter.reset();
  extfilt.reset();

  bus_value = 0;
  bus_value_ttl = 0;
}


// ----------------------------------------------------------------------------
// Write 16-bit sample to audio input.
// NB! The caller is responsible for keeping the value within 16 bits.
// Note that to mix in an external audio signal, the signal should be
// resampled to 1MHz first to avoid sampling noise.
// ----------------------------------------------------------------------------
void SIDFP::input(int sample)
{
  // Voice outputs are 20 bits. Scale up to match three voices in order
  // to facilitate simulation of the MOS8580 "digi boost" hardware hack.
  ext_in = (sample << 4)*3 - 0x20000;
}

float SIDFP::output()
{
  const float range = 1 << 15;
  return extfilt.output() / (4095.f * 255.f * 3.f / range);
}

// ----------------------------------------------------------------------------
// Read registers.
//
// Reading a write only register returns the last byte written to any SID
// register. The individual bits in this value start to fade down towards
// zero after a few cycles. All bits reach zero within approximately
// $2000 - $4000 cycles.
// It has been claimed that this fading happens in an orderly fashion, however
// sampling of write only registers reveals that this is not the case.
// NB! This is not correctly modeled.
// The actual use of write only registers has largely been made in the belief
// that all SID registers are readable. To support this belief the read
// would have to be done immediately after a write to the same register
// (remember that an intermediate write to another register would yield that
// value instead). With this in mind we return the last value written to
// any SID register for $2000 cycles without modeling the bit fading.
// ----------------------------------------------------------------------------
reg8 SIDFP::read(reg8 offset)
{
  switch (offset) {
  case 0x19:
    return potx.readPOT();
  case 0x1a:
    return poty.readPOT();
  case 0x1b:
    return voice[2].wave.readOSC();
  case 0x1c:
    return voice[2].envelope.readENV();
  default:
    return bus_value;
  }
}


// ----------------------------------------------------------------------------
// Write registers.
// ----------------------------------------------------------------------------
void SIDFP::write(reg8 offset, reg8 value)
{
  bus_value = value;
  bus_value_ttl = 0x4000;

  switch (offset) {
  case 0x00:
    voice[0].wave.writeFREQ_LO(value);
    break;
  case 0x01:
    voice[0].wave.writeFREQ_HI(value);
    break;
  case 0x02:
    voice[0].wave.writePW_LO(value);
    break;
  case 0x03:
    voice[0].wave.writePW_HI(value);
    break;
  case 0x04:
    voice[0].writeCONTROL_REG(value);
    break;
  case 0x05:
    voice[0].envelope.writeATTACK_DECAY(value);
    break;
  case 0x06:
    voice[0].envelope.writeSUSTAIN_RELEASE(value);
    break;
  case 0x07:
    voice[1].wave.writeFREQ_LO(value);
    break;
  case 0x08:
    voice[1].wave.writeFREQ_HI(value);
    break;
  case 0x09:
    voice[1].wave.writePW_LO(value);
    break;
  case 0x0a:
    voice[1].wave.writePW_HI(value);
    break;
  case 0x0b:
    voice[1].writeCONTROL_REG(value);
    break;
  case 0x0c:
    voice[1].envelope.writeATTACK_DECAY(value);
    break;
  case 0x0d:
    voice[1].envelope.writeSUSTAIN_RELEASE(value);
    break;
  case 0x0e:
    voice[2].wave.writeFREQ_LO(value);
    break;
  case 0x0f:
    voice[2].wave.writeFREQ_HI(value);
    break;
  case 0x10:
    voice[2].wave.writePW_LO(value);
    break;
  case 0x11:
    voice[2].wave.writePW_HI(value);
    break;
  case 0x12:
    voice[2].writeCONTROL_REG(value);
    break;
  case 0x13:
    voice[2].envelope.writeATTACK_DECAY(value);
    break;
  case 0x14:
    voice[2].envelope.writeSUSTAIN_RELEASE(value);
    break;
  case 0x15:
    filter.writeFC_LO(value);
    break;
  case 0x16:
    filter.writeFC_HI(value);
    break;
  case 0x17:
    filter.writeRES_FILT(value);
    break;
  case 0x18:
    filter.writeMODE_VOL(value);
    break;
  default:
    break;
  }
}


// ----------------------------------------------------------------------------
// Constructor.
// ----------------------------------------------------------------------------
SIDFP::State::State()
{
  int i;

  for (i = 0; i < 0x20; i++) {
    sid_register[i] = 0;
  }

  bus_value = 0;
  bus_value_ttl = 0;

  for (i = 0; i < 3; i++) {
    accumulator[i] = 0;
    shift_register[i] = 0x7ffff8;
    rate_counter[i] = 0;
    rate_counter_period[i] = 9;
    exponential_counter[i] = 0;
    exponential_counter_period[i] = 1;
    envelope_counter[i] = 0;
    envelope_state[i] = EnvelopeGeneratorFP::RELEASE;
    hold_zero[i] = true;
  }
}


// ----------------------------------------------------------------------------
// Read state.
// ----------------------------------------------------------------------------
SIDFP::State SIDFP::read_state()
{
  State state;
  int i, j;

  for (i = 0, j = 0; i < 3; i++, j += 7) {
    WaveformGeneratorFP& wave = voice[i].wave;
    EnvelopeGeneratorFP& envelope = voice[i].envelope;
    state.sid_register[j + 0] = wave.freq & 0xff;
    state.sid_register[j + 1] = wave.freq >> 8;
    state.sid_register[j + 2] = wave.pw & 0xff;
    state.sid_register[j + 3] = wave.pw >> 8;
    state.sid_register[j + 4] =
      (wave.waveform << 4)
      | (wave.test ? 0x08 : 0)
      | (wave.ring_mod ? 0x04 : 0)
      | (wave.sync ? 0x02 : 0)
      | (envelope.gate ? 0x01 : 0);
    state.sid_register[j + 5] = (envelope.attack << 4) | envelope.decay;
    state.sid_register[j + 6] = (envelope.sustain << 4) | envelope.release;
  }

  state.sid_register[j++] = filter.fc & 0x007;
  state.sid_register[j++] = filter.fc >> 3;
  state.sid_register[j++] = (filter.res << 4) | filter.filt;
  state.sid_register[j++] =
    (filter.voice3off ? 0x80 : 0)
    | (filter.hp_bp_lp << 4)
    | filter.vol;

  // These registers are superfluous, but included for completeness.
  for (; j < 0x1d; j++) {
    state.sid_register[j] = read(j);
  }
  for (; j < 0x20; j++) {
    state.sid_register[j] = 0;
  }

  state.bus_value = bus_value;
  state.bus_value_ttl = bus_value_ttl;

  for (i = 0; i < 3; i++) {
    state.accumulator[i] = voice[i].wave.accumulator;
    state.shift_register[i] = voice[i].wave.shift_register;
    state.rate_counter[i] = voice[i].envelope.rate_counter;
    state.rate_counter_period[i] = voice[i].envelope.rate_period;
    state.exponential_counter[i] = voice[i].envelope.exponential_counter;
    state.exponential_counter_period[i] = voice[i].envelope.exponential_counter_period;
    state.envelope_counter[i] = voice[i].envelope.envelope_counter;
    state.envelope_state[i] = voice[i].envelope.state;
    state.hold_zero[i] = voice[i].envelope.hold_zero;
  }

  return state;
}


// ----------------------------------------------------------------------------
// Write state.
// ----------------------------------------------------------------------------
void SIDFP::write_state(const State& state)
{
  int i;

  for (i = 0; i <= 0x18; i++) {
    write(i, state.sid_register[i]);
  }

  bus_value = state.bus_value;
  bus_value_ttl = state.bus_value_ttl;

  for (i = 0; i < 3; i++) {
    voice[i].wave.accumulator = state.accumulator[i];
    voice[i].wave.shift_register = state.shift_register[i];
    voice[i].envelope.rate_counter = state.rate_counter[i];
    voice[i].envelope.rate_period = state.rate_counter_period[i];
    voice[i].envelope.exponential_counter = state.exponential_counter[i];
    voice[i].envelope.exponential_counter_period = state.exponential_counter_period[i];
    voice[i].envelope.envelope_counter = state.envelope_counter[i];
    voice[i].envelope.state = state.envelope_state[i];
    voice[i].envelope.hold_zero = state.hold_zero[i];
  }
}


// ----------------------------------------------------------------------------
// Enable filter.
// ----------------------------------------------------------------------------
void SIDFP::enable_filter(bool enable)
{
  filter.enable_filter(enable);
}


// ----------------------------------------------------------------------------
// Enable external filter.
// ----------------------------------------------------------------------------
void SIDFP::enable_external_filter(bool enable)
{
  extfilt.enable_filter(enable);
}


// ----------------------------------------------------------------------------
// I0() computes the 0th order modified Bessel function of the first kind.
// This function is originally from resample-1.5/filterkit.c by J. O. Smith.
// ----------------------------------------------------------------------------
double SIDFP::I0(double x)
{
  // Max error acceptable in I0.
  const double I0e = 1e-6;

  double sum, u, halfx, temp;
  int n;

  sum = u = n = 1;
  halfx = x/2.0;

  do {
    temp = halfx/n++;
    u *= temp*temp;
    sum += u;
  } while (u >= I0e*sum);

  return sum;
}


// ----------------------------------------------------------------------------
// Setting of SID sampling parameters.
//
// Use a clock freqency of 985248Hz for PAL C64, 1022730Hz for NTSC C64.
// The default end of passband frequency is pass_freq = 0.9*sample_freq/2
// for sample frequencies up to ~ 44.1kHz, and 20kHz for higher sample
// frequencies.
//
// For resampling, the ratio between the clock frequency and the sample
// frequency is limited as follows:
//   125*clock_freq/sample_freq < 16384
// E.g. provided a clock frequency of ~ 1MHz, the sample frequency can not
// be set lower than ~ 8kHz. A lower sample frequency would make the
// resampling code overfill its 16k sample ring buffer.
// 
// The end of passband frequency is also limited:
//   pass_freq <= 0.9*sample_freq/2

// E.g. for a 44.1kHz sampling rate the end of passband frequency is limited
// to slightly below 20kHz. This constraint ensures that the FIR table is
// not overfilled.
// ----------------------------------------------------------------------------
bool SIDFP::set_sampling_parameters(double clock_freq, sampling_method method,
				  double sample_freq, double pass_freq)
{
  // Check resampling constraints.
  if (method == SAMPLE_RESAMPLE_INTERPOLATE || method == SAMPLE_RESAMPLE_FAST)
  {
    // Check whether the sample ring buffer would overfill.
    if (FIR_N*clock_freq/sample_freq >= RINGSIZE) {
      return false;
    }

    // The default passband limit is 0.9*sample_freq/2 for sample
    // frequencies below ~ 44.1kHz, and 20kHz for higher sample frequencies.
    if (pass_freq < 0) {
      pass_freq = 20000;
      if (2*pass_freq/sample_freq >= 0.9) {
	pass_freq = 0.9*sample_freq/2;
      }
    }
    // Check whether the FIR table would overfill.
    else if (pass_freq > 0.9*sample_freq/2) {
      return false;
    }
  }

  clock_frequency = clock_freq;
  sampling = method;

  filter.set_clock_frequency(clock_freq);
  extfilt.set_clock_frequency(clock_freq);
  adjust_sampling_frequency(sample_freq);

  sample_offset = 0;
  sample_prev = 0;

  // FIR initialization is only necessary for resampling.
  if (method != SAMPLE_RESAMPLE_INTERPOLATE && method != SAMPLE_RESAMPLE_FAST)
  {
    delete[] sample;
    delete[] fir;
    sample = 0;
    fir = 0;
    return true;
  }

  // 16 bits -> -96dB stopband attenuation.
  const double A = -20*log10(1.0/(1 << 16));
  // A fraction of the bandwidth is allocated to the transition band,
  double dw = (1 - 2*pass_freq/sample_freq)*M_PI;
  // The cutoff frequency is midway through the transition band.
  double wc = (2*pass_freq/sample_freq + 1)*M_PI/2;

  // For calculation of beta and N see the reference for the kaiserord
  // function in the MATLAB Signal Processing Toolbox:
  // http://www.mathworks.com/access/helpdesk/help/toolbox/signal/kaiserord.html
  const double beta = 0.1102*(A - 8.7);
  const double I0beta = I0(beta);

  // The filter order will maximally be 124 with the current constraints.
  // N >= (96.33 - 7.95)/(2.285*0.1*M_PI) -> N >= 123
  // The filter order is equal to the number of zero crossings, i.e.
  // it should be an even number (sinc is symmetric about x = 0).
  int N = int((A - 7.95)/(2.285*dw) + 0.5);
  N += N & 1;

  double f_samples_per_cycle = sample_freq/clock_freq;
  double f_cycles_per_sample = clock_freq/sample_freq;

  // The filter length is equal to the filter order + 1.
  // The filter length must be an odd number (sinc is symmetric about x = 0).
  fir_N = int(N*f_cycles_per_sample) + 1;
  fir_N |= 1;

  // We clamp the filter table resolution to 2^n, making the fixpoint
  // sample_offset a whole multiple of the filter table resolution.
  int res = method == SAMPLE_RESAMPLE_INTERPOLATE ?
    (int)FIR_RES_INTERPOLATE : (int)FIR_RES_FAST;
  int n = (int)ceil(log(res/f_cycles_per_sample)/log(2.0));
  fir_RES = 1 << n;

  // Allocate memory for FIR tables.
  delete[] fir;
  fir = new float[fir_N*fir_RES];

  // Calculate fir_RES FIR tables for linear interpolation.
  for (int i = 0; i < fir_RES; i++) {
    int fir_offset = i*fir_N + fir_N/2;
    double j_offset = double(i)/fir_RES;
    // Calculate FIR table. This is the sinc function, weighted by the
    // Kaiser window.
    for (int j = -fir_N/2; j <= fir_N/2; j++) {
      double jx = j - j_offset;
      double wt = wc*jx/f_cycles_per_sample;
      double temp = jx/(fir_N/2);
      double Kaiser =
	fabs(temp) <= 1 ? I0(beta*sqrt(1 - temp*temp))/I0beta : 0;
      double sincwt =
	fabs(wt) >= 1e-6 ? sin(wt)/wt : 1;
      fir[fir_offset + j] = f_samples_per_cycle*wc/M_PI*sincwt*Kaiser;
    }
  }

  // Allocate sample buffer.
  if (!sample) {
    sample = new float[RINGSIZE*2];
  }
  // Clear sample buffer.
  for (int j = 0; j < RINGSIZE*2; j++) {
    sample[j] = 0;
  }
  sample_index = 0;

  return true;
}


// ----------------------------------------------------------------------------
// Adjustment of SID sampling frequency.
//
// In some applications, e.g. a C64 emulator, it can be desirable to
// synchronize sound with a timer source. This is supported by adjustment of
// the SID sampling frequency.
//
// NB! Adjustment of the sampling frequency may lead to noticeable shifts in
// frequency, and should only be used for interactive applications. Note also
// that any adjustment of the sampling frequency will change the
// characteristics of the resampling filter, since the filter is not rebuilt.
// ----------------------------------------------------------------------------
void SIDFP::adjust_sampling_frequency(double sample_freq)
{
  cycles_per_sample = clock_frequency/sample_freq;
}

void SIDFP::age_bus_value(cycle_count n) {
  if (bus_value_ttl != 0) {
    bus_value_ttl -= n;
    if (bus_value_ttl <= 0) {
        bus_value = 0;
        bus_value_ttl = 0;
    }
  }
}

// ----------------------------------------------------------------------------
// SID clocking - 1 cycle.
// ----------------------------------------------------------------------------
void SIDFP::clock()
{
  int i;

  // Clock amplitude modulators.
  for (i = 0; i < 3; i++) {
    voice[i].envelope.clock();
  }

  // Clock oscillators.
  for (i = 0; i < 3; i++) {
    voice[i].wave.clock();
  }

  // Synchronize oscillators.
  for (i = 0; i < 3; i++) {
    voice[i].wave.synchronize();
  }

  // Clock filter.
  extfilt.clock(filter.clock(voice[0].output(), voice[1].output(), voice[2].output(), ext_in));
}

// ----------------------------------------------------------------------------
// SID clocking with audio sampling.
// Fixpoint arithmetics is used.
//
// The example below shows how to clock the SID a specified amount of cycles
// while producing audio output:
//
// while (delta_t) {
//   bufindex += sid.clock(delta_t, buf + bufindex, buflength - bufindex);
//   write(dsp, buf, bufindex*2);
//   bufindex = 0;
// }
// 
// ----------------------------------------------------------------------------
int SIDFP::clock(cycle_count& delta_t, short* buf, int n, int interleave)
{
  /* XXX I assume n is generally large enough for delta_t here... */
  age_bus_value(delta_t);
  /* disable denormal numbers */
#ifdef __SSE__
  int old = 0;
  if (detect_sse() == 1)
  {
    old = _mm_getcsr();
    _mm_setcsr(old | _MM_FLUSH_ZERO_ON); /* denormals-are-zero appropriate for SSE2 boxes, I'll play this safe */
  }
#endif
  int res;
  switch (sampling) {
  default:
  case SAMPLE_INTERPOLATE:
    res = clock_interpolate(delta_t, buf, n, interleave);
    break;
  case SAMPLE_RESAMPLE_INTERPOLATE:
    res = clock_resample_interpolate(delta_t, buf, n, interleave);
    break;
  case SAMPLE_RESAMPLE_FAST:
    res = clock_resample_fast(delta_t, buf, n, interleave);
    break;
  }
#ifdef __SSE__
  if (detect_sse() == 1)
  {
    _mm_setcsr(old);
  }
#endif
  return res;
}

// ----------------------------------------------------------------------------
// SID clocking with audio sampling - cycle based with linear sample
// interpolation.
//
// Here the chip is clocked every cycle. This yields higher quality
// sound since the samples are linearly interpolated, and since the
// external filter attenuates frequencies above 16kHz, thus reducing
// sampling noise.
// ----------------------------------------------------------------------------
RESID_INLINE
int SIDFP::clock_interpolate(cycle_count& delta_t, short* buf, int n,
			   int interleave)
{
  int s = 0;
  int i;

  for (;;) {
    float next_sample_offset = sample_offset + cycles_per_sample;
    int delta_t_sample = (int) next_sample_offset;
    if (delta_t_sample > delta_t) {
      break;
    }
    if (s >= n) {
      return s;
    }
    for (i = 0; i < delta_t_sample - 1; i++) {
      clock();
    }
    if (i < delta_t_sample) {
      sample_prev = output();
      clock();
    }

    delta_t -= delta_t_sample;
    sample_offset = next_sample_offset - delta_t_sample;

    float sample_now = output();
    int v = (int)(sample_prev + (sample_offset * (sample_now - sample_prev)));
    // Saturated arithmetics to guard against 16 bit sample overflow.
    const int half = 1 << 15;
    if (v >= half) {
      v = half - 1;
    }
    else if (v < -half) {
      v = -half;
    }
    buf[s++*interleave] = v;

    sample_prev = sample_now;
  }

  for (i = 0; i < delta_t - 1; i++) {
    clock();
  }
  if (i < delta_t) {
    sample_prev = output();
    clock();
  }
  sample_offset -= delta_t;
  delta_t = 0;
  return s;
}

static float convolve(const float *a, const float *b, int n)
{
    float out = 0.f;
#ifdef __SSE__
    if (detect_sse() == 1)
    {
        __m128 out4 = { 0, 0, 0, 0 };

        /* examine if we can use aligned loads on both pointers */
        int diff = (int) (a - b) & 0xf;
        /* long cast is no-op for x86-32, but x86-64 gcc needs 64 bit intermediate
         * to convince compiler we mean this. */
        unsigned int a_align = (unsigned int) (unsigned long) a & 0xf;

        /* advance if necessary. We can't let n fall < 0, so no while (n --). */
        while (n > 0 && a_align != 0 && a_align != 16) {
            out += (*(a ++)) * (*(b ++));
            n --;
            a_align += 4;
        }

        int n4 = n / 4;
        if (diff == 0) {
            for (int i = 0; i < n4; i ++) {
                out4 = _mm_add_ps(out4, _mm_mul_ps(_mm_load_ps(a), _mm_load_ps(b)));
                a += 4;
                b += 4;
            }
        } else {
        /* XXX loadu is 4x slower than load, at least. We could at 4x memory
         * use prepare versions of b aligned for any a alignment. We could
         * also issue aligned loads and shuffle the halves at each iteration.
         * Initial results indicate only very small improvements. */
            for (int i = 0; i < n4; i ++) {
                out4 = _mm_add_ps(out4, _mm_mul_ps(_mm_load_ps(a), _mm_loadu_ps(b)));
                a += 4;
                b += 4;
            }
        }

        out4 = _mm_add_ps(_mm_movehl_ps(out4, out4), out4);
        out4 = _mm_add_ss(_mm_shuffle_ps(out4, out4, 1), out4);
        float out_tmp;
        _mm_store_ss(&out_tmp, out4);
        out += out_tmp;

        n &= 3;
        /* fallthrough for last values */
    }
#endif
    while (n --)
        out += (*(a ++)) * (*(b ++));

    return out;
}

// ----------------------------------------------------------------------------
// SID clocking with audio sampling - cycle based with audio resampling.
//
// This is the theoretically correct (and computationally intensive) audio
// sample generation. The samples are generated by resampling to the specified
// sampling frequency. The work rate is inversely proportional to the
// percentage of the bandwidth allocated to the filter transition band.
//
// This implementation is based on the paper "A Flexible Sampling-Rate
// Conversion Method", by J. O. Smith and P. Gosset, or rather on the
// expanded tutorial on the "Digital Audio Resampling Home Page":
// http://www-ccrma.stanford.edu/~jos/resample/
//
// By building shifted FIR tables with samples according to the
// sampling frequency, this implementation dramatically reduces the
// computational effort in the filter convolutions, without any loss
// of accuracy. The filter convolutions are also vectorizable on
// current hardware.
//
// Further possible optimizations are:
// * An equiripple filter design could yield a lower filter order, see
//   http://www.mwrf.com/Articles/ArticleID/7229/7229.html
// * The Convolution Theorem could be used to bring the complexity of
//   convolution down from O(n*n) to O(n*log(n)) using the Fast Fourier
//   Transform, see http://en.wikipedia.org/wiki/Convolution_theorem
// * Simply resampling in two steps can also yield computational
//   savings, since the transition band will be wider in the first step
//   and the required filter order is thus lower in this step.
//   Laurent Ganier has found the optimal intermediate sampling frequency
//   to be (via derivation of sum of two steps):
//     2 * pass_freq + sqrt [ 2 * pass_freq * orig_sample_freq
//       * (dest_sample_freq - 2 * pass_freq) / dest_sample_freq ]
//
// NB! the result of right shifting negative numbers is really
// implementation dependent in the C++ standard.
// ----------------------------------------------------------------------------
RESID_INLINE
int SIDFP::clock_resample_interpolate(cycle_count& delta_t, short* buf, int n,
				    int interleave)
{
  int s = 0;

  for (;;) {
    float next_sample_offset = sample_offset + cycles_per_sample;
    /* full clocks left to next sample */
    int delta_t_sample = (int) next_sample_offset;
    if (delta_t_sample > delta_t || s >= n)
      break;

    /* clock forward delta_t_sample samples */
    for (int i = 0; i < delta_t_sample; i++) {
      clock();
      sample[sample_index] = sample[sample_index + RINGSIZE] = output();
      ++ sample_index;
      sample_index &= RINGSIZE - 1;
    }
    delta_t -= delta_t_sample;

    /* Phase of the sample in terms of clock, [0 .. 1[. */
    sample_offset = next_sample_offset - (float) delta_t_sample;

    /* find the first of the nearest fir tables close to the phase */
    float fir_offset_rmd = sample_offset * fir_RES;
    int fir_offset = (int) fir_offset_rmd;
    /* [0 .. 1[ */
    fir_offset_rmd -= (float) fir_offset;

    /* find fir_N most recent samples, plus one extra in case the FIR wraps. */
    float* sample_start = sample + sample_index - fir_N + RINGSIZE - 1;

    float v1 = convolve(sample_start, fir + fir_offset * fir_N, fir_N);
    // Use next FIR table, wrap around to first FIR table using
    // previous sample.
    if (++ fir_offset == fir_RES) {
      fir_offset = 0;
      ++ sample_start;
    }
    float v2 = convolve(sample_start, fir + fir_offset * fir_N, fir_N);

    // Linear interpolation between the sinc tables yields good approximation
    // for the exact value.
    int v = (int) (v1 + fir_offset_rmd * (v2 - v1));

    // Saturated arithmetics to guard against 16 bit sample overflow.
    const int half = 1 << 15;
    if (v >= half) {
      v = half - 1;
    }
    else if (v < -half) {
      v = -half;
    }

    buf[s ++ * interleave] = v;
  }

  /* clock forward delta_t samples */
  for (int i = 0; i < delta_t; i++) {
    clock();
    sample[sample_index] = sample[sample_index + RINGSIZE] = output();
    ++ sample_index;
    sample_index &= RINGSIZE - 1;
  }
  sample_offset -= (float) delta_t;
  delta_t = 0;
  return s;
}


// ----------------------------------------------------------------------------
// SID clocking with audio sampling - cycle based with audio resampling.
// ----------------------------------------------------------------------------
RESID_INLINE
int SIDFP::clock_resample_fast(cycle_count& delta_t, short* buf, int n,
			     int interleave)
{
  int s = 0;

  for (;;) {
    float next_sample_offset = sample_offset + cycles_per_sample;
    int delta_t_sample = (int) next_sample_offset;
    if (delta_t_sample > delta_t || s >= n)
      break;

    for (int i = 0; i < delta_t_sample; i++) {
      clock();
      sample[sample_index] = sample[sample_index + RINGSIZE] = output();
      ++ sample_index;
      sample_index &= RINGSIZE - 1;
    }
    delta_t -= delta_t_sample;

    sample_offset = next_sample_offset - (float) delta_t_sample;

    int fir_offset = (int) (sample_offset * fir_RES);
    float* sample_start = sample + sample_index - fir_N + RINGSIZE;

    int v = (int)convolve(sample_start, fir + fir_offset * fir_N, fir_N);

    // Saturated arithmetics to guard against 16 bit sample overflow.
    const int half = 1 << 15;
    if (v >= half) {
      v = half - 1;
    }
    else if (v < -half) {
      v = -half;
    }

    buf[s ++ * interleave] = v;
  }

  for (int i = 0; i < delta_t; i++) {
    clock();
    sample[sample_index] = sample[sample_index + RINGSIZE] = output();
    ++ sample_index;
    sample_index &= RINGSIZE - 1;
  }
  sample_offset -= (float) delta_t;
  delta_t = 0;
  return s;
}
