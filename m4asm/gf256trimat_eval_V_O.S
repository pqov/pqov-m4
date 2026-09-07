.syntax unified
.cpu cortex-m4
.thumb

#include "params.h"
#include "gf256trimat_eval.i"


//void gf256trimat_eval_m4f_V_O(uint32_t *c, uint32_t *a, uint8_t *b);
#if (_O_BYTE == 44) || (_O_BYTE == 45)
.global gf256trimat_eval_m4f_V_O
.type gf256trimat_eval_m4f_V_O, %function
.align 2
gf256trimat_eval_m4f_V_O:
    gf256_trimat_eval _V, _O_BYTE
#endif
