#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include "libc_impl.h"
#include "helpers.h"

#define RM_RN 0
#define RM_RZ 1
#define RM_RP 2
#define RM_RM 3

#define cvt_w_d(f) \
    ((fcsr & RM_RZ) ? ((isnan(f) || f <= -2147483649.0 || f >= 2147483648.0) ? (fcsr |= 0x40, 2147483647) : (int)f) : (assert(0), 0))

#define cvt_w_s(f) cvt_w_d((double)f)

static union FloatReg f0 = {{0, 0}}, f2 = {{0, 0}}, f4 = {{0, 0}}, f6 = {{0, 0}}, f8 = {{0, 0}},
f10 = {{0, 0}}, f12 = {{0, 0}}, f14 = {{0, 0}}, f16 = {{0, 0}}, f18 = {{0, 0}}, f20 = {{0, 0}},
f22 = {{0, 0}}, f24 = {{0, 0}}, f26 = {{0, 0}}, f28 = {{0, 0}}, f30 = {{0, 0}};
static uint32_t fcsr = 1;

static inline double double_from_FloatReg(union FloatReg floatreg) {
    uint64_t val;

    val = floatreg.w[1];
    val <<= 32;
    val |= floatreg.w[0];
    return *(double*)&val;
}
static inline union FloatReg FloatReg_from_double(double d) {
    uint64_t val = *(uint64_t*)&d;
    union FloatReg floatreg;

    floatreg.w[0] = (val) & 0xFFFFFFFF;
    floatreg.w[1] = (val >> 32) & 0xFFFFFFFF;

    return floatreg;
}
