#ifndef GF256_ASM__H
#define GF256_ASM__H

#include <stdint.h>
#include "utils_prng.h"

// gf256mat_prod.S
void gf256mat_prod_m4f_OO_V_normal_normal(uint8_t *c, const uint8_t *matA, const uint8_t *b);
void gf256mat_prod_m4f_V_O_normal_normal(uint8_t *c, const uint8_t *matA, const uint8_t *b);
void gf256mat_prod_m4f_OO_X_normal_normal(uint8_t *c, const uint8_t *matA, const uint8_t *b, size_t n_A_width);
void gf256mat_prod_m4f_V_X_normal_normal(uint8_t *c, const uint8_t *matA, const uint8_t *b, size_t n_A_width);
void gf256mat_prod_m4f_O_X_normal_normal(uint8_t *c, const uint8_t *matA, const uint8_t *b, size_t n_A_width);

// gf256trimat_eval_V_O.S
void gf256trimat_eval_m4f_V_O(uint8_t * y, const uint8_t * trimat, const uint8_t * x);

// gf256trimat_eval_N_O_publicinputs.S
void gf256trimat_eval_m4f_N_O_publicinputs(uint8_t * y, const uint8_t * trimat, const uint8_t * x);

// gf256trimat_eval_N_O_incremental_publicinputs.S
void gf256trimat_eval_m4f_N_O_incremental_publicinputs(uint8_t * y, prng_publicinputs_t *prng, const uint8_t * trimat, const uint8_t * x);

// gf256trimat_2trimat_madd_V_O.S
void gf256trimat_2trimat_madd_m4f_V_O(uint8_t *c, const uint8_t *a, const uint8_t *b);

// gf256mat_gauss_elim_O.S
uint8_t gf256mat_gauss_elim_row_echolen_m4f_O(uint8_t *mat);

#endif