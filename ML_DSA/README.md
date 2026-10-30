/*
 * ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm.
 * Supports ML-DSA-44, ML-DSA-65 and ML-DSA-87 selected at run time.
*/
#ifndef MLDSA_H
#define MLDSA_H
#include <stddef.h>
#include <stdint.h>

#define MLDSA_44 44
#define MLDSA_65 65
#define MLDSA_87 87

#define MLDSA44_PK_BYTES   1312
#define MLDSA44_SK_BYTES   2560
#define MLDSA44_SIG_BYTES  2420
#define MLDSA65_PK_BYTES   1952
#define MLDSA65_SK_BYTES   4032
#define MLDSA65_SIG_BYTES  3309
#define MLDSA87_PK_BYTES   2592
#define MLDSA87_SK_BYTES   4896
#define MLDSA87_SIG_BYTES  4627

#define MLDSA_MAX_PK_BYTES   MLDSA87_PK_BYTES
#define MLDSA_MAX_SK_BYTES   MLDSA87_SK_BYTES
#define MLDSA_MAX_SIG_BYTES  MLDSA87_SIG_BYTES

#define MLDSA_SEED_BYTES 32
#define MLDSA_RND_BYTES  32

#define MLDSA_OK            0
#define MLDSA_ERR_PARAM    (-1)  /* bad level / null pointer / ctx too long */
#define MLDSA_ERR_RNG      (-2)
#define MLDSA_ERR_MEM      (-3)
#define MLDSA_ERR_SIGN     (-4)  /* rejection-loop exhausted (practically unreachable) */
#define MLDSA_ERR_VERIFY   (-5)  /* signature invalid */

size_t mldsa_pk_bytes(int level);   /* 0 on bad level */
size_t mldsa_sk_bytes(int level);
size_t mldsa_sig_bytes(int level);

/* Supply your own CSPRNG by replacing this (default: /dev/urandom, see randombytes.c). */
int mldsa_randombytes(uint8_t *out, size_t len);

/* ML-DSA.KeyGen: random seed xi. */
int mldsa_keygen(int level, uint8_t *pk, uint8_t *sk);
/* ML-DSA.KeyGen_internal: deterministic from 32-byte seed xi. */
int mldsa_keygen_internal(int level, uint8_t *pk, uint8_t *sk, const uint8_t xi[32]);

/*
 * ML-DSA.Sign (pure, with context string, |ctx| <= 255).
 * rnd: 32 bytes of randomness; pass NULL for the default hedged mode (fresh
 * random bytes), or 32 zero bytes for the deterministic variant.
 * On success *siglen = mldsa_sig_bytes(level).
 */
int mldsa_sign(int level, uint8_t *sig, size_t *siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t *ctx, size_t ctxlen,
               const uint8_t *sk, const uint8_t rnd[32]);

/* ML-DSA.Verify (pure). Returns 0 if valid, MLDSA_ERR_VERIFY if invalid. */
int mldsa_verify(int level, const uint8_t *sig, size_t siglen,
                 const uint8_t *m, size_t mlen,
                 const uint8_t *ctx, size_t ctxlen,
                 const uint8_t *pk);

/*
 * Internal interfaces operate on M' = pre || msg (the two parts are simply
 * concatenated; pass pre=NULL,prelen=0 to supply a complete M').
 */
int mldsa_sign_internal(int level, uint8_t *sig, size_t *siglen,
                        const uint8_t *pre, size_t prelen,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *sk, const uint8_t rnd[32]);
int mldsa_verify_internal(int level, const uint8_t *sig, size_t siglen,
                          const uint8_t *pre, size_t prelen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *pk);
#endif
