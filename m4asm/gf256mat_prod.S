.syntax unified
.cpu cortex-m4
.thumb

#include "params.h"
#include "gf256mat_prod.i"


//void gf256mat_prod_m4f_OO_V_normal_normal(uint32_t *c, uint32_t *a, uint8_t *b);
#if ((_O*_O_BYTE) % 4 == 0) && (_V % 4 == 0)
.global gf256mat_prod_m4f_OO_V_normal_normal
.type gf256mat_prod_m4f_OO_V_normal_normal, %function
.align 2
gf256mat_prod_m4f_OO_V_normal_normal:
    gf256_mat_prod (_O*_O_BYTE), _V
#else
//void gf256mat_prod_m4f_OO_X_normal_normal(uint32_t *c, uint32_t *a, uint8_t *b, size_t n_A_width);
.global gf256mat_prod_m4f_OO_X_normal_normal
.type gf256mat_prod_m4f_OO_X_normal_normal, %function
.align 2
gf256mat_prod_m4f_OO_X_normal_normal:
    gf256_mat_prod_x (_O*_O_BYTE)
#endif

//void gf256mat_prod_m4f_V_O_normal_normal(uint32_t *c, uint32_t *a, uint8_t *b);
#if (_V_BYTE % 4 == 0) && (_O % 4 == 0)
.global gf256mat_prod_m4f_V_O_normal_normal
.type gf256mat_prod_m4f_V_O_normal_normal, %function
.align 2
gf256mat_prod_m4f_V_O_normal_normal:
    gf256_mat_prod _V_BYTE, _O
#else
//void gf256mat_prod_m4f_V_X_normal_normal(uint32_t *c, uint32_t *a, uint8_t *b, size_t n_A_width);
.global gf256mat_prod_m4f_V_X_normal_normal
.type gf256mat_prod_m4f_V_X_normal_normal, %function
.align 2
gf256mat_prod_m4f_V_X_normal_normal:
    gf256_mat_prod_x _V_BYTE
#endif

//void gf256mat_prod_m4f_O_X_normal_normal(uint32_t *c, uint32_t *a, uint8_t *b, size_t n_A_width);
.global gf256mat_prod_m4f_O_X_normal_normal
.type gf256mat_prod_m4f_O_X_normal_normal, %function
.align 2
gf256mat_prod_m4f_O_X_normal_normal:
    gf256_mat_prod_x _O_BYTE
