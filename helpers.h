#ifndef HELPERS_H
#define HELPERS_H

#include <stdint.h>

#define MEM_U32(a) (*(uint32_t *)(mem + a))
#define MEM_S32(a) (*(int32_t *)(mem + a))
#define MEM_U16(a) (*(uint16_t *)(mem + ((a) ^ 2)))
#define MEM_S16(a) (*(int16_t *)(mem + ((a) ^ 2)))
#define MEM_U8(a) (*(uint8_t *)(mem + ((a) ^ 3)))
#define MEM_S8(a) (*(int8_t *)(mem + ((a) ^ 3)))

#define MEM_F32(a) (*(float *)(mem + a))

static inline double MEM_F64_aux(uint8_t *mem, uint32_t a) {
    uint64_t val;

    val = MEM_U32(a);
    val <<= 32;
    val |= MEM_U32(a + 4);
    return *(double*)&val;
}


#define MEM_F64(a) (MEM_F64_aux(mem, a))

#endif
