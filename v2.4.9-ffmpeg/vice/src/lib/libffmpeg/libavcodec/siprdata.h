/*
 * SIPR / ACELP.NET decoder
 *
 * Copyright (c) 2008 Vladimir Voroshilov
 * Copyright (c) 2009 Vitor Sessak
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

#ifndef AVCODEC_SIPRDATA_H
#define AVCODEC_SIPRDATA_H

static const float mean_lsf[10] = {
    0.297151,  0.452308,  0.765443,  1.134803,  1.421125,
    1.773822,  2.049173,  2.375914,  2.585097,  0.075756
};

static const float lsf_cb1[64][2] = {
    { 0.007587, -0.005843}, { 0.042163, -0.028048}, {-0.017147, -0.060705},
    { 0.013773, -0.038108}, {-0.041563, -0.078571}, {-0.076928, -0.119343},
    { 0.012654,  0.176005}, { 0.059737,  0.156869}, { 0.171767,  0.231837},
    { 0.114030,  0.242047}, { 0.168977,  0.283101}, { 0.146210,  0.397961},
    { 0.249446,  0.268421}, { 0.137074,  0.186724}, {-0.057736, -0.135638},
    {-0.109664, -0.124611}, {-0.021234, -0.031174}, {-0.013990, -0.091819},
    {-0.040046, -0.111426}, {-0.016830,  0.055361}, { 0.057815,  0.071606},
    { 0.060670,  0.114436}, { 0.106695,  0.140838}, { 0.093601,  0.092793},
    { 0.039593,  0.006142}, {-0.066589, -0.092463}, {-0.102589, -0.171380},
    {-0.059621, -0.050671}, { 0.166131,  0.139773}, { 0.213069,  0.190761},
    { 0.061820,  0.037661}, { 0.136471,  0.090823}, {-0.019789,  0.013515},
    { 0.022280,  0.079473}, { 0.215281,  0.461959}, { 0.206497,  0.340077},
    { 0.012249, -0.065596}, { 0.091345,  0.190871}, { 0.019506,  0.037266},
    {-0.050702, -0.013223}, {-0.057334,  0.028943}, { 0.291512,  0.371415},
    {-0.053467,  0.084160}, { 0.025372,  0.375310}, { 0.269995,  0.566520},
    {-0.095259, -0.012353}, { 0.050479,  0.212893}, { 0.101219,  0.049320},
    { 0.072426,  0.283362}, {-0.084116, -0.150542}, {-0.031485,  0.144922},
    { 0.012714,  0.256910}, {-0.009528,  0.102768}, {-0.039572,  0.204967},
    {-0.098800,  0.055038}, { 0.020719,  0.128387}, {-0.045559, -0.178373},
    {-0.082338,  0.136933}, {-0.058270,  0.292806}, { 0.084242,  0.505112},
    { 0.121825,  0.326386}, {-0.102658, -0.069341}, { 0.071675,  0.004744},
    {-0.117763, -0.202608}
};

static const float lsf_cb2[128][2] = {
    { 0.025412,  0.006095}, {-0.069803,  0.010650}, {-0.175957, -0.185800},
    {-0.139298, -0.048013}, {-0.156150, -0.129688}, {-0.160523,  0.068022},
    { 0.199683,  0.259982}, { 0.258038,  0.236147}, { 0.367089,  0.304716},
    { 0.251764,  0.305853}, { 0.394314,  0.382153}, { 0.448579,  0.337438},
    { 0.323286,  0.425563}, { 0.015369,  0.123820}, {-0.026770,  0.083881},
    {-0.112161, -0.097993}, {-0.221847, -0.161311}, {-0.050014, -0.092862},
    {-0.214960, -0.398498}, {-0.114062, -0.241381}, { 0.137950,  0.138852},
    { 0.031529,  0.065719}, { 0.208734,  0.084760}, { 0.157862,  0.057535},
    { 0.124750,  0.011922}, {-0.035227, -0.154397}, {-0.105523, -0.291427},
    {-0.073488, -0.201948}, {-0.224184, -0.273290}, {-0.168019, -0.240297},
    {-0.271591, -0.384682}, {-0.124784,  0.014253}, { 0.004210, -0.110418},
    { 0.074270, -0.014272}, { 0.053058, -0.068672}, {-0.090098, -0.145019},
    { 0.303214,  0.210323}, { 0.413443,  0.272002}, { 0.356904,  0.230646},
    {-0.035186, -0.028579}, {-0.117558,  0.115105}, {-0.159225,  0.218385},
    {-0.230178,  0.172901}, {-0.216148, -0.110195}, { 0.309444,  0.101508},
    { 0.250489,  0.118338}, { 0.293324,  0.151205}, {-0.023634,  0.033084},
    { 0.076708,  0.114024}, { 0.123119,  0.087704}, {-0.060265,  0.126543},
    {-0.223766, -0.021903}, {-0.241987, -0.328089}, { 0.205598,  0.147925},
    {-0.087010,  0.064601}, {-0.287892, -0.286099}, {-0.179451, -0.350781},
    {-0.219572,  0.043816}, {-0.217263,  0.245550}, {-0.286743, -0.180981},
    { 0.172659,  0.112620}, {-0.105422,  0.176856}, { 0.006176, -0.051491},
    { 0.099802,  0.176322}, {-0.186620, -0.068980}, { 0.164689,  0.185018},
    { 0.519877,  0.376111}, { 0.521941,  0.533731}, { 0.473375,  0.439534},
    { 0.214235,  0.202476}, { 0.579215,  0.466969}, { 0.310414,  0.271057},
    { 0.257450,  0.058939}, { 0.023936, -0.169464}, {-0.268817, -0.064531},
    {-0.174182, -0.000198}, {-0.268405, -0.234529}, {-0.296522,  0.247140},
    { 0.115950, -0.072194}, {-0.303666,  0.149084}, {-0.347762, -0.011002},
    {-0.223829, -0.214137}, {-0.278958, -0.457975}, { 0.135500,  0.238466},
    { 0.312730,  0.342760}, { 0.071754, -0.125912}, { 0.485938,  0.260429},
    { 0.037536,  0.179771}, { 0.391493,  0.156938}, { 0.397320,  0.484446},
    {-0.308630, -0.342418}, {-0.269599, -0.128453}, {-0.086683, -0.043863},
    { 0.421115,  0.213521}, { 0.082417,  0.049006}, {-0.087873,  0.238126},
    { 0.338899,  0.166131}, {-0.166988,  0.147105}, {-0.167214, -0.294075},
    { 0.588706,  0.328303}, { 0.207270,  0.017671}, {-0.141658,  0.291147},
    {-0.140850,  0.374321}, { 0.028180,  0.322510}, {-0.229858,  0.328036},
    {-0.060743, -0.260916}, {-0.011131,  0.246442}, {-0.058151,  0.310760},
    {-0.127536, -0.186432}, {-0.128523, -0.334884}, {-0.283899,  0.077729},
    {-0.031595,  0.181015}, {-0.329330, -0.108630}, {-0.215739,  0.107458},
    { 0.175734,  0.327134}, { 0.255801,  0.176077}, { 0.228265,  0.396859},
    {-0.370909, -0.185081}, {-0.355138, -0.300405}, { 0.061669,  0.242616},
    { 0.104489,  0.307995}, {-0.320021, -0.234002}, { 0.077349,  0.416286},
    {-0.339471, -0.407609}, {-0.019384, -0.215111}, { 0.168229, -0.032453},
    {-0.040140,  0.399658}, {-0.275141,  0.008218}
};

static const float lsf_cb3[128][2] = {
    { 0.024608,  0.006198}, {-0.216616, -0.398169}, {-0.089601, -0.201370},
    {-0.121878, -0.305281}, { 0.037913,  0.059320}, { 0.245126,  0.244089},
    { 0.266853,  0.182476}, { 0.319362,  0.203481}, { 0.349945,  0.252644},
    { 0.393849,  0.279272}, { 0.445707,  0.258063}, { 0.387321,  0.200855},
    {-0.038818,  0.129603}, {-0.009510,  0.076441}, {-0.023892, -0.028199},
    {-0.117134, -0.145990}, {-0.186585, -0.052886}, {-0.034250, -0.084547},
    {-0.087443, -0.095426}, {-0.453322, -0.174493}, {-0.363975, -0.148186},
    {-0.334413, -0.202479}, {-0.221313, -0.181320}, {-0.131146, -0.050611},
    {-0.104706,  0.115139}, { 0.192765,  0.275417}, { 0.014184,  0.194251},
    { 0.154215,  0.226949}, { 0.084031,  0.221759}, { 0.189438,  0.164566},
    { 0.130737,  0.170962}, {-0.066815,  0.062954}, {-0.177176, -0.145167},
    {-0.247608, -0.129767}, {-0.187886, -0.293720}, {-0.244036, -0.344655},
    {-0.203063, -0.234947}, {-0.292715, -0.158421}, { 0.064990, -0.028164},
    { 0.147664,  0.085995}, { 0.107977,  0.002253}, { 0.071286,  0.027533},
    { 0.021017, -0.049807}, {-0.272056, -0.217857}, {-0.065596,  0.008375},
    {-0.150818, -0.195514}, {-0.012767, -0.150787}, { 0.238541,  0.136606},
    { 0.291741,  0.114024}, { 0.202677,  0.103701}, { 0.140985,  0.037759},
    {-0.257347, -0.442383}, {-0.320666, -0.319742}, {-0.488725, -0.603660},
    {-0.319170, -0.469806}, { 0.014970, -0.101074}, { 0.102209,  0.066790},
    {-0.076202, -0.044884}, { 0.073868,  0.152565}, { 0.070755, -0.091358},
    {-0.016751,  0.027216}, { 0.071201,  0.096981}, {-0.060975, -0.145638},
    { 0.114156,  0.117587}, {-0.284757, -0.029101}, {-0.253005, -0.073645},
    {-0.204028, -0.098492}, {-0.114508,  0.001219}, {-0.225284, -0.011998},
    {-0.235670,  0.084330}, { 0.161921,  0.128334}, { 0.025717,  0.119456},
    {-0.255292, -0.281471}, {-0.392803, -0.095809}, { 0.039229, -0.152110},
    {-0.310905, -0.099233}, {-0.268773,  0.032308}, {-0.340150,  0.013129},
    {-0.344890, -0.045157}, {-0.188423,  0.265603}, {-0.168235, -0.000936},
    { 0.000462,  0.297000}, { 0.263674,  0.371214}, {-0.146797, -0.098225},
    {-0.386557, -0.282426}, {-0.070940, -0.255550}, { 0.293258,  0.252785},
    { 0.408332,  0.387751}, {-0.381914, -0.358918}, {-0.463621, -0.315560},
    {-0.323681, -0.258465}, { 0.250055,  0.071195}, {-0.405256, -0.429754},
    {-0.135748, -0.251274}, { 0.186827,  0.060177}, { 0.116742, -0.053526},
    {-0.403321, -0.220339}, {-0.414144, -0.021108}, {-0.416877,  0.050184},
    {-0.470083, -0.079564}, {-0.315554,  0.219217}, {-0.273183,  0.138437},
    { 0.253231,  0.306374}, { 0.177802,  0.346298}, { 0.210358,  0.207697},
    {-0.323480,  0.077519}, {-0.193136,  0.048170}, { 0.114492,  0.292778},
    {-0.130766,  0.056677}, {-0.171572, -0.349267}, {-0.370076, -0.536392},
    {-0.311109, -0.389953}, { 0.334928,  0.367664}, { 0.351246,  0.438664},
    { 0.518803,  0.331253}, { 0.437061,  0.327257}, { 0.318906,  0.307389},
    {-0.025972, -0.206758}, { 0.373278,  0.325438}, { 0.473488,  0.389441},
    { 0.478553,  0.477990}, { 0.332783,  0.153825}, { 0.212098,  0.452336},
    { 0.161522, -0.011212}, { 0.209368,  0.020687}, {-0.086262,  0.204493},
    {-0.388643,  0.133640}, {-0.177016,  0.134404}
};

static const float lsf_cb4[128][2] = {
    {-0.003594, -0.022447}, { 0.070651,  0.028334}, {-0.290374, -0.018347},
    {-0.224495, -0.370312}, {-0.269555, -0.131227}, {-0.122714, -0.267733},
    { 0.173325,  0.138698}, { 0.161946,  0.020687}, { 0.111706,  0.022510},
    { 0.097638,  0.056049}, { 0.139754,  0.059920}, { 0.056549, -0.050586},
    { 0.036301,  0.021501}, {-0.066347,  0.012324}, {-0.066972,  0.096136},
    {-0.120062, -0.084201}, { 0.011225,  0.047425}, {-0.012846, -0.067390},
    {-0.116201,  0.122874}, {-0.027819,  0.035453}, {-0.024743,  0.072835},
    {-0.034061, -0.001310}, { 0.077469,  0.081609}, { 0.128347,  0.139584},
    { 0.183416,  0.086563}, {-0.155839, -0.053775}, {-0.190403, -0.018639},
    {-0.202548, -0.062841}, {-0.373733, -0.275094}, {-0.394260, -0.186513},
    {-0.465700, -0.220031}, { 0.064400, -0.095825}, {-0.262053, -0.199837},
    {-0.167233, -0.094402}, { 0.048600,  0.057567}, {-0.007122,  0.168506},
    { 0.050938,  0.156451}, {-0.060828,  0.147083}, {-0.171889,  0.195822},
    {-0.218934,  0.138431}, {-0.270532,  0.195775}, {-0.405818,  0.075643},
    {-0.440187,  0.193387}, {-0.484968,  0.157607}, {-0.480560,  0.067230},
    {-0.436757, -0.111847}, {-0.040731, -0.040363}, {-0.202319, -0.170457},
    {-0.158515, -0.134551}, {-0.356709, -0.378549}, {-0.268820, -0.289831},
    {-0.188486, -0.289306}, {-0.148139, -0.177616}, {-0.071591, -0.191128},
    {-0.052270, -0.150589}, {-0.020543, -0.116220}, { 0.039584, -0.012592},
    {-0.268226,  0.042704}, {-0.209755,  0.069423}, {-0.168964,  0.124504},
    {-0.363240,  0.188266}, {-0.524935, -0.025010}, {-0.105894, -0.002699},
    {-0.251830, -0.062018}, {-0.310480, -0.082325}, { 0.014652,  0.083127},
    {-0.136512,  0.033116}, {-0.073755, -0.025236}, { 0.110766,  0.095954},
    { 0.002878,  0.011838}, {-0.074977, -0.244586}, {-0.047023, -0.081339},
    {-0.183249,  0.029525}, { 0.263435,  0.206934}, {-0.156721, -0.229993},
    {-0.112224, -0.208941}, {-0.116534, -0.123191}, {-0.073988, -0.111668},
    { 0.029484, -0.137573}, {-0.009802, -0.161685}, {-0.023273,  0.114043},
    {-0.332651,  0.049072}, {-0.394009,  0.018608}, {-0.433543, -0.035318},
    {-0.368459, -0.108024}, {-0.350215, -0.037617}, {-0.321140, -0.178537},
    { 0.020307, -0.048487}, {-0.210512, -0.232274}, {-0.082140, -0.065443},
    { 0.081961, -0.009340}, { 0.146794,  0.101973}, { 0.213999,  0.124687},
    { 0.100217, -0.054095}, {-0.114411, -0.041403}, {-0.097631,  0.037061},
    {-0.099651, -0.157978}, {-0.215790, -0.116550}, {-0.107100,  0.076300},
    { 0.084653,  0.126088}, { 0.246439,  0.091442}, { 0.160077,  0.188536},
    { 0.273900,  0.279190}, { 0.320417,  0.232550}, { 0.132710, -0.018988},
    { 0.018950, -0.091681}, {-0.032073, -0.202906}, { 0.212789,  0.178188},
    { 0.208580,  0.239726}, { 0.049420,  0.099840}, {-0.145695, -0.010619},
    {-0.132525, -0.322660}, { 0.019666,  0.126603}, { 0.260809,  0.147727},
    {-0.232795, -0.001090}, {-0.049826,  0.225987}, {-0.154774,  0.076614},
    { 0.045032,  0.221397}, { 0.321014,  0.161632}, {-0.062379,  0.053586},
    { 0.132252,  0.246675}, { 0.392627,  0.271905}, {-0.264585,  0.102344},
    {-0.327200,  0.121624}, {-0.399642,  0.124445}, {-0.108335,  0.179171},
    { 0.100374,  0.182731}, { 0.203852,  0.049505}
};

static const float lsf_cb5[32][2] = {
    {-0.047705,  0.008002}, { 0.011332,  0.065028}, {-0.021796, -0.034777},
    {-0.147394, -0.001241}, {-0.001577,  0.020599}, {-0.083827, -0.028975},
    {-0.177707,  0.066046}, {-0.043241, -0.165144}, { 0.053322,  0.096519},
    {-0.097688,  0.106484}, {-0.023392,  0.111234}, {-0.146747, -0.159360},
    { 0.027241, -0.011806}, {-0.043156,  0.057667}, { 0.019516, -0.062116},
    { 0.025990,  0.162533}, { 0.091888,  0.009720}, {-0.098511,  0.036414},
    { 0.013722, -0.116512}, { 0.054833, -0.180975}, { 0.119497,  0.128774},
    { 0.118378, -0.125997}, { 0.065882, -0.030932}, { 0.120581, -0.039964},
    {-0.050561, -0.088577}, { 0.050134,  0.033194}, {-0.129654, -0.075112},
    {-0.225334, -0.040234}, { 0.070629, -0.084455}, { 0.095508,  0.063548},
    { 0.150514,  0.034366}, { 0.186092, -0.069272}
};

static const float * const lsf_codebooks[] = {
    lsf_cb1[0], lsf_cb2[0], lsf_cb3[0], lsf_cb4[0], lsf_cb5[0]
};

static const float gain_cb[128][2] = {
    {0.035230, 0.161540}, {0.049223, 0.448359}, {0.057443, 0.809043},
    {0.072434, 1.760306}, {0.111491, 0.566418}, {0.112820, 1.098524},
    {0.143493, 0.726856}, {0.144840, 0.347800}, {0.180341, 1.050010},
    {0.188171, 2.197256}, {0.189771, 0.256947}, {0.198260, 0.484678},
    {0.210622, 0.755825}, {0.220694, 0.590788}, {0.237062, 1.322214},
    {0.255175, 0.338710}, {0.298980, 0.919051}, {0.314627, 0.520961},
    {0.337106, 1.469863}, {0.341422, 2.804546}, {0.363257, 0.736222},
    {0.363881, 0.367640}, {0.369850, 1.937934}, {0.370136, 1.075201},
    {0.397152, 0.549410}, {0.426557, 0.876015}, {0.450686, 0.215588},
    {0.468116, 0.671848}, {0.470495, 1.242034}, {0.474180, 1.739845},
    {0.484875, 0.490564}, {0.498917, 0.971238}, {0.530996, 0.785765},
    {0.539768, 2.130689}, {0.546021, 0.589544}, {0.546632, 3.050846},
    {0.552336, 0.389775}, {0.556302, 1.400103}, {0.559688, 1.105421},
    {0.574140, 0.667513}, {0.595547, 0.828943}, {0.597771, 0.496929},
    {0.617079, 1.863075}, {0.619657, 1.221713}, {0.621172, 0.950275},
    {0.628426, 0.630766}, {0.628689, 4.242164}, {0.640899, 1.529846},
    {0.645813, 0.331127}, {0.653056, 0.748168}, {0.662909, 1.077438},
    {0.669505, 2.631114}, {0.681570, 1.839298}, {0.687844, 0.903400},
    {0.688660, 1.270830}, {0.695070, 0.578227}, {0.697926, 0.428440},
    {0.715454, 0.812355}, {0.729981, 1.539357}, {0.737434, 1.106765},
    {0.740241, 2.033374}, {0.740871, 0.568460}, {0.752689, 0.698461},
    {0.756587, 0.893078}, {0.767797, 0.499246}, {0.768516, 3.712434},
    {0.773153, 1.332360}, {0.786125, 1.042996}, {0.788792, 0.238388},
    {0.790861, 2.273229}, {0.795338, 1.582767}, {0.809621, 0.595501},
    {0.821032, 0.756460}, {0.824590, 0.922925}, {0.826019, 1.186793},
    {0.827426, 1.885076}, {0.830080, 6.088666}, {0.837028, 2.819993},
    {0.845561, 1.490623}, {0.848323, 0.410436}, {0.856522, 0.729725},
    {0.862636, 0.966880}, {0.874561, 1.681660}, {0.874751, 1.177630},
    {0.879289, 2.301300}, {0.886671, 0.613068}, {0.896729, 0.781097},
    {0.904777, 3.484111}, {0.906098, 1.330892}, {0.919182, 1.877203},
    {0.919901, 0.569511}, {0.921772, 1.034126}, {0.922439, 0.376000},
    {0.934221, 1.485214}, {0.938842, 0.869135}, {0.939166, 2.378294},
    {0.958933, 1.122722}, {0.959042, 0.694098}, {0.960995, 1.743430},
    {0.970763, 2.884897}, {0.982881, 0.814506}, {0.990141, 1.330022},
    {0.996447, 1.823381}, {1.000013, 0.967498}, {1.000743, 0.480597},
    {1.008020, 5.095226}, {1.013883, 2.105435}, {1.026438, 0.691312},
    {1.027361, 1.558169}, {1.030123, 3.586526}, {1.033916, 1.118036},
    {1.039315, 2.543360}, {1.068596, 0.836380}, {1.081023, 1.318768},
    {1.093150, 2.267843}, {1.095607, 1.712383}, {1.102816, 1.037334},
    {1.103231, 3.536292}, {1.107320, 0.508615}, {1.150000, 7.999000},
    {1.156731, 1.236772}, {1.168428, 2.268084}, {1.184130, 0.775839},
    {1.210609, 1.511840}, {1.220663, 4.365683}, {1.224016, 0.983179},
    {1.252236, 2.778535}, {1.301176, 1.923126}
};

static const float pred[4] = {
    0.200, 0.334, 0.504, 0.691
};

#endif /* AVCODEC_SIPRDATA_H */
