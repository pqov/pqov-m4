// GF16 multiplication for uint32_t (i.e., 8 elements packed into one register)

.macro gf16_madd_precompb fbx0, fbx1, fbx2, fbx3, bb, tmp1
    vmov.w \fbx0, \bb

    and.w \tmp1, \bb, #8
    eor.w \bb, \bb, \tmp1
    lsr.w \tmp1, \tmp1, #3
    add.w \tmp1, \tmp1, \tmp1, lsl#1
    eor.w \bb, \tmp1, \bb, lsl#1
    vmov.w \fbx1, \bb

    and.w \tmp1, \bb, #8
    eor.w \bb, \bb, \tmp1
    lsr.w \tmp1, \tmp1, #3
    add.w \tmp1, \tmp1, \tmp1, lsl#1
    eor.w \bb, \tmp1, \bb, lsl#1
    vmov.w \fbx2, \bb

    and.w \tmp1, \bb, #8
    eor.w \bb, \bb, \tmp1
    lsr.w \tmp1, \tmp1, #3
    add.w \tmp1, \tmp1, \tmp1, lsl#1
    eor.w \bb, \tmp1, \bb, lsl#1
    vmov.w \fbx3, \bb
.endm


.macro gf16_madd_inner k, num, acc0, acc1, acc2, acc3, aa0, aa1, aa2, aa3, fbx, c11111111, tmp0, tmp1
    vmov.w \tmp1, \fbx

    and.w \tmp0, \c11111111, \aa0, lsr\k
    mul.w \tmp0, \tmp1, \tmp0
    eor.w \acc0, \acc0, \tmp0

    .if \num >= 2
    and.w \tmp0, \c11111111, \aa1, lsr\k
    mul.w \tmp0, \tmp1, \tmp0
    eor.w \acc1, \acc1, \tmp0
    .endif

    .if \num >= 3
    and.w \tmp0, \c11111111, \aa2, lsr\k
    mul.w \tmp0, \tmp1, \tmp0
    eor.w \acc2, \acc2, \tmp0
    .endif

    .if \num >= 4
    and.w \tmp0, \c11111111, \aa3, lsr\k
    mul.w \tmp0, \tmp1, \tmp0
    eor.w \acc3, \acc3, \tmp0
    .endif
.endm


.macro gf16_madd num, acc0, acc1, acc2, acc3, aa0, aa1, aa2, aa3, fbx0, fbx1, fbx2, fbx3, c11111111, tmp0, tmp1
    gf16_madd_inner #0, \num, \acc0, \acc1, \acc2, \acc3, \aa0, \aa1, \aa2, \aa3, \fbx0, \c11111111, \tmp0, \tmp1
    gf16_madd_inner #1, \num, \acc0, \acc1, \acc2, \acc3, \aa0, \aa1, \aa2, \aa3, \fbx1, \c11111111, \tmp0, \tmp1
    gf16_madd_inner #2, \num, \acc0, \acc1, \acc2, \acc3, \aa0, \aa1, \aa2, \aa3, \fbx2, \c11111111, \tmp0, \tmp1
    gf16_madd_inner #3, \num, \acc0, \acc1, \acc2, \acc3, \aa0, \aa1, \aa2, \aa3, \fbx3, \c11111111, \tmp0, \tmp1
.endm
