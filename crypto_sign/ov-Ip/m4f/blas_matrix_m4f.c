#include "blas_matrix_m4f.h"
#include "blas_matrix_ref.h"
#include "blas.h"
#include "params.h"
#include "config.h"

#ifdef _USE_GF16
#include "gf16_asm.h"
#else
#include "gf256_asm.h"
#endif

//TODO: check if this can be removed
#include "parallel_matrix_op.h"
#include "ov_keypair_computation.h"

static inline
void gf256mat_submat( uint8_t * mat2 , unsigned veclen2_byte , unsigned st , const uint8_t * mat , unsigned veclen_byte , unsigned n_vec )
{
    for(unsigned i=0;i<n_vec;i++) {
        for(unsigned j=0;j<veclen2_byte;j++) mat2[i*veclen2_byte+j] = mat[i*veclen_byte+st+j];
    }
}

#ifdef _USE_GF16
void gf16mat_prod_m4f(uint8_t *c, const uint8_t *matA, unsigned n_A_vec_byte, unsigned n_A_width, const uint8_t *b)
{
  //TODO: add errors if used with different params
  if(n_A_vec_byte == 2048 && n_A_width == 96){
    gf16mat_prod_m4f_2048_96_normal_normal(c, matA, b);
  } else if(n_A_vec_byte == 48 && n_A_width == 64){
    gf16mat_prod_m4f_48_64_normal_normal(c, matA, b);
  } else if(n_A_vec_byte == 32){
    gf16mat_prod_m4f_32_X_normal_normal(c, matA, b, n_A_width);
  }
}


void batch_quad_trimat_eval_gf16_m4f(unsigned char * y, const unsigned char * trimat,
                                     const unsigned char * x, unsigned dim , unsigned size_batch)
{
  // TODO: add errors if this is not the case
  if(dim == 96 && size_batch == 32){
    gf16trimat_eval_m4f_96_32(y, trimat, x);
  }
}

unsigned gf16mat_gaussian_elim_m4f(uint8_t *sqmat_a , uint8_t *constant, unsigned len) {
  //TODO: add errors if _O is different
  (void) len;
  uint8_t mat[_O*(_O_BYTE+4)];
  for(unsigned i=0;i<_O;i++) {
      uint8_t * ai = mat + i*(_O_BYTE+4);
      for(unsigned j=0;j<_O;j++) {
         // transpose since sqmat_a is col-major
         gf16v_set_ele( ai , j , gf16v_get_ele(sqmat_a+j*_O_BYTE,i) );
      }
      ai[_O_BYTE] = gf16v_get_ele(constant,i);
  }

  unsigned char r8 = gf16mat_gauss_elim_row_echolen_m4f_64(mat);

  for(unsigned i=0;i<_O;i++) {
      uint8_t * ai = mat + i*(_O_BYTE+4);
      memcpy( sqmat_a+i*_O_BYTE , ai  , _O_BYTE ); // output a row-major matrix
      gf16v_set_ele(constant,i, ai[_O_BYTE] );
  }
  return r8;
}
#else

void gf256mat_prod_m4f(uint8_t *c, const uint8_t *matA, unsigned n_A_vec_byte, unsigned n_A_width, const uint8_t *b){
#if ((_O*_O_BYTE) % 4 == 0) && (_V % 4 == 0)
  if(n_A_vec_byte == (_O*_O_BYTE) && n_A_width == _V){
    gf256mat_prod_m4f_OO_V_normal_normal(c, matA, b);
    return;
  }
#else
  if(n_A_vec_byte == (_O*_O_BYTE)){
    gf256mat_prod_m4f_OO_X_normal_normal(c, matA, b, n_A_width);
    return;
  }
#endif
#if (_V_BYTE % 4 == 0) && (_O % 4 == 0)
  if(n_A_vec_byte == _V_BYTE && n_A_width == _O) {
    gf256mat_prod_m4f_V_O_normal_normal(c, matA, b);
    return;
  }
#else
  if(n_A_vec_byte == _V_BYTE) {
    gf256mat_prod_m4f_V_X_normal_normal(c, matA, b, n_A_width);
    return;
  }
#endif
  if(n_A_vec_byte == _O_BYTE) {
    gf256mat_prod_m4f_O_X_normal_normal(c, matA, b, n_A_width);
    return;
  }
  gf256mat_prod_ref(c, matA, n_A_vec_byte, n_A_width, b);
}

void batch_quad_trimat_eval_gf256_m4f(unsigned char * y, const unsigned char * trimat, const unsigned char * x, unsigned dim , unsigned size_batch){
#if (_O_BYTE == 44) || (_O_BYTE == 45)
  if(dim == _V && size_batch == _O_BYTE){
      gf256trimat_eval_m4f_V_O(y, trimat, x);
      return;
  }
#endif
  batch_quad_trimat_eval_gf256(y, trimat, x, dim, size_batch);
}

#if (_O_BYTE > 47)
unsigned gf256mat_gaussian_elim_m4f(uint8_t *sqmat_a , uint8_t *constant, unsigned len){
  return gf256mat_gaussian_elim_ref(sqmat_a, constant, len);
}
#else
#define GE_ROW_STRIDE 48
unsigned gf256mat_gaussian_elim_m4f(uint8_t *sqmat_a , uint8_t *constant, unsigned len){
  (void) len;
  uint8_t mat[_O*GE_ROW_STRIDE];
   for(unsigned i=0;i<_O;i++) {
       uint8_t * ai = mat + i*GE_ROW_STRIDE;
       for(unsigned j=0;j<_O;j++) {
           // transpose since sqmat_a is col-major
           ai[j] = sqmat_a[j*_O_BYTE+i];
       }
       ai[_O_BYTE] = constant[i];
   }

   unsigned char r8 = gf256mat_gauss_elim_row_echolen_m4f_O(mat);

   for(unsigned i=0;i<_O;i++) {
       uint8_t * ai = mat + i*GE_ROW_STRIDE;
       memcpy( sqmat_a + i*_O_BYTE , ai , _O_BYTE);     // output a row-major matrix
       constant[i] = ai[_O_BYTE];
   }
   return r8;
}
#undef GE_ROW_STRIDE
#endif

#endif

#if defined(_OV_PKC) || defined(_OV_PKC_SKC)
void ov_pkc_calculate_F_from_Q_m4f( sk_t * Fs)
{
  // TODO: add errors if parameters change
  #ifdef _USE_GF16
    gf16trimat_2trimat_madd_m4f_96_48_64_32( Fs->S , Fs->P1 , Fs->O);
  #elif (_O_BYTE == 44) || (_O_BYTE == 45)
    gf256trimat_2trimat_madd_m4f_V_O( Fs->S , Fs->P1 , Fs->O);
  #else
    calculate_F2( Fs->S , Fs->P1 , Fs->S , Fs->O );
  #endif
}
#endif

