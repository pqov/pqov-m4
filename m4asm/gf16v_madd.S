.syntax unified
.cpu cortex-m4
.thumb

#include "gf16_madd.i"

// void gf16v_madd_m4f(uint8_t *accu_c, const uint8_t *a, uint8_t gf16_b, unsigned num_byte);
.global gf16v_madd_m4f
.type gf16v_madd_m4f, %function
.align 2
gf16v_madd_m4f:
    push {r4-r11, lr}

    cc    .req r0
    aa    .req r1
    bb    .req r2
    ctr   .req r3
    c1111 .req r12
    tmp0  .req r14
    tmp1  .req r2

    fbx0 .req s0
    fbx1 .req s1
    fbx2 .req s2
    fbx3 .req s3

    and.w bb, bb, #0xf
    mov.w c1111, #0x11111111
    gf16_madd_precompb fbx0, fbx1, fbx2, fbx3, bb, r4

    1:
    cmp.w ctr, #16
    blo.w 2f
    ldr.w r4, [aa, #0]
    ldr.w r5, [aa, #4]
    ldr.w r6, [aa, #8]
    ldr.w r7, [aa, #12]
    ldr.w r8, [cc, #0]
    ldr.w r9, [cc, #4]
    ldr.w r10, [cc, #8]
    ldr.w r11, [cc, #12]
    gf16_madd 4, r8, r9, r10, r11, r4, r5, r6, r7, fbx0, fbx1, fbx2, fbx3, c1111, tmp0, tmp1
    str.w r8, [cc, #0]
    str.w r9, [cc, #4]
    str.w r10, [cc, #8]
    str.w r11, [cc, #12]
    add.w aa, #16
    add.w cc, #16
    sub.w ctr, #16
    b 1b

    2:
    cmp.w ctr, #12
    blo.w 3f
    ldr.w r4, [aa, #0]
    ldr.w r5, [aa, #4]
    ldr.w r6, [aa, #8]
    ldr.w r8, [cc, #0]
    ldr.w r9, [cc, #4]
    ldr.w r10, [cc, #8]
    gf16_madd 3, r8, r9, r10, xxx, r4, r5, r6, xxx, fbx0, fbx1, fbx2, fbx3, c1111, tmp0, tmp1
    str.w r8, [cc, #0]
    str.w r9, [cc, #4]
    str.w r10, [cc, #8]
    add.w aa, #12
    add.w cc, #12
    sub.w ctr, #12
    b 5f

    3:
    cmp.w ctr, #8
    blo.w 4f
    ldr.w r4, [aa, #0]
    ldr.w r5, [aa, #4]
    ldr.w r8, [cc, #0]
    ldr.w r9, [cc, #4]
    gf16_madd 2, r8, r9, xxx, xxx, r4, r5, xxx, xxx, fbx0, fbx1, fbx2, fbx3, c1111, tmp0, tmp1
    str.w r8, [cc, #0]
    str.w r9, [cc, #4]
    add.w aa, #8
    add.w cc, #8
    sub.w ctr, #8
    b 5f

    4:
    cmp.w ctr, #4
    blo.w 5f
    ldr.w r4, [aa, #0]
    ldr.w r8, [cc, #0]
    gf16_madd 1, r8, xxx, xxx, xxx, r4, xxx, xxx, xxx, fbx0, fbx1, fbx2, fbx3, c1111, tmp0, tmp1
    str.w r8, [cc, #0]
    add.w aa, #4
    add.w cc, #4
    sub.w ctr, #4

    5:
    cmp.w ctr, #0
    beq.w 9f
    ldrb.w r4, [aa, #0]
    ldrb.w r8, [cc, #0]
    cmp.w ctr, #1
    beq.w 6f
    ldrb.w r5, [aa, #1]
    orr.w r4, r4, r5, lsl#8
    ldrb.w r5, [cc, #1]
    orr.w r8, r8, r5, lsl#8
    cmp.w ctr, #2
    beq.w 6f
    ldrb.w r5, [aa, #2]
    orr.w r4, r4, r5, lsl#16
    ldrb.w r5, [cc, #2]
    orr.w r8, r8, r5, lsl#16
    6:
    gf16_madd 1, r8, xxx, xxx, xxx, r4, xxx, xxx, xxx, fbx0, fbx1, fbx2, fbx3, c1111, tmp0, tmp1
    strb.w r8, [cc, #0]
    cmp.w ctr, #1
    beq.w 9f
    lsr.w r5, r8, #8
    strb.w r5, [cc, #1]
    cmp.w ctr, #2
    beq.w 9f
    lsr.w r5, r8, #16
    strb.w r5, [cc, #2]

    9:
    pop {r4-r11, pc}
