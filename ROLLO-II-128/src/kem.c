/** 
 * \file kem.c
 * \brief Implementation of api.h
 */

#include "api.h"
#include "ffi_qre.h"
#include "hash.h"
#include "parameters.h"
#include "string.h"
#include "rsr_algorithm.h"
#include "rolloII_types.h"
#include "parsing.h"

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk) {
  secretKey skTmp;
  publicKey pkTmp;

  ffi_field_init();
  ffi_qre_init_modulus(PARAM_N);

  unsigned char sk_seed[SEEDEXPANDER_SEED_BYTES];
  randombytes(sk_seed, SEEDEXPANDER_SEED_BYTES);

  rolloII_secret_key_from_string(&skTmp, sk_seed);

  ffi_qre invX;
  ffi_qre_init(&invX);
  ffi_qre_inv(invX, skTmp.x);

  ffi_qre_init(&(pkTmp.h));
  ffi_qre_mul(pkTmp.h, invX, skTmp.y);

  rolloII_secret_key_to_string(sk, sk_seed);
  rolloII_public_key_to_string(sk + SEEDEXPANDER_SEED_BYTES, &pkTmp);
  rolloII_public_key_to_string(pk, &pkTmp);

  #ifdef VERBOSE
    printf("\n\nsk_seed: "); for(int i = 0 ; i < SEEDEXPANDER_SEED_BYTES ; ++i) printf("%02x", sk_seed[i]);
    printf("\n\nx: "); ffi_qre_print(skTmp.x);
    printf("\n\ny: "); ffi_qre_print(skTmp.y);
    printf("\n\nx^-1: "); ffi_qre_print(invX);
    printf("\n\nh: "); ffi_qre_print(pkTmp.h);
    printf("\n\nsk: "); for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) printf("%02x", sk[i]);
    printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
  #endif

  ffi_qre_clear(invX);
  ffi_vspace_clear(skTmp.F, PARAM_D);
  ffi_qre_clear(skTmp.x);
  ffi_qre_clear(skTmp.y);
  ffi_qre_clear(pkTmp.h);
  ffi_qre_clear_modulus();

  return 0;
}

int crypto_kem_enc(unsigned char* ct, unsigned char* m, unsigned char* pk) {
  publicKey pkTmp;
  ciphertext ctTmp;

  ffi_field_init();
  ffi_qre_init_modulus(PARAM_N);

  rolloII_public_key_from_string(&pkTmp, pk);

  ffi_vspace E;
  ffi_vspace_init(&E, PARAM_R);

  //Computing m
    
  //randombytes(m, CRYPTO_BYTES);

  //Generating G function
  //AES_XOF_struct G_seedexpander;
  //seedexpander_init(&G_seedexpander, m, m + 32, SEEDEXPANDER_MAX_LENGTH);

  // Computing theta
  unsigned char theta[SEEDEXPANDER_SEED_BYTES];
  //seedexpander(&G_seedexpander, theta, SEEDEXPANDER_SEED_BYTES);

  //Seedexpander used to encrypt
  AES_XOF_struct encSeedexpander;
  seedexpander_init(&encSeedexpander, theta, theta + 32, SEEDEXPANDER_MAX_LENGTH);

  //Support
  ffi_vspace_set_random_full_rank(E, PARAM_R, &encSeedexpander);

  ffi_poly E1, E2;

  ffi_qre_init(&E1);
  ffi_qre_init(&E2);
  ffi_qre_init(&(ctTmp.syndrom));

  //Random error vectors
  ffi_qre_set_random_from_support(E1, E, PARAM_R, &encSeedexpander);
  ffi_qre_set_random_from_support(E2, E, PARAM_R, &encSeedexpander);

  ffi_qre_mul(ctTmp.syndrom, E2, pkTmp.h);
  ffi_qre_add(ctTmp.syndrom, ctTmp.syndrom, E1);

  ffi_vec_echelonize(E, PARAM_R);

  unsigned char support[FFI_VEC_R_BYTES], hashSupp[CRYPTO_BYTES];
  ffi_vec_to_string_compact(support, E, PARAM_R);
  sha512(hashSupp, support, FFI_VEC_R_BYTES);

  for(int i=0 ; i<CRYPTO_BYTES ; i++) {
    ctTmp.v[i] = m[i] ^ hashSupp[i];
  }
  
    

  sha512(ctTmp.d, m, CRYPTO_BYTES);


  //Ciphertext parsing
  rolloII_ciphertext_to_string(ct, &ctTmp);

  return 0;
}

int crypto_kem_dec(unsigned char* m, unsigned char* ct, unsigned char* sk) {
  secretKey skTmp;
  ciphertext ctTmp;

  ffi_field_init();
  ffi_qre_init_modulus(PARAM_N);

  rolloII_secret_key_from_string(&skTmp, sk);
  rolloII_ciphertext_from_string(&ctTmp, ct);

  ffi_qre xc;
  ffi_qre_init(&xc);

  ffi_qre_mul(xc, skTmp.x, ctTmp.syndrom);

  ffi_vspace E;
  unsigned int dimE = 0;

  ffi_vspace_init(&E, PARAM_N);

  dimE = rank_support_recoverer(E, PARAM_R, skTmp.F, PARAM_D, xc, PARAM_N);

  unsigned char decryptedE[SHA512_BYTES];

  if(dimE != 0) {
    unsigned char support[FFI_VEC_R_BYTES];
    ffi_vec_to_string_compact(support, E, PARAM_R);
    sha512(decryptedE, support, FFI_VEC_R_BYTES);
  } else {
    memset(decryptedE, 0, SHARED_SECRET_BYTES);
  }

  

  for(int i=0 ; i<CRYPTO_BYTES ; i++) {
    m[i] = decryptedE[i] ^ ctTmp.v[i];
  }

  return 0;
}
