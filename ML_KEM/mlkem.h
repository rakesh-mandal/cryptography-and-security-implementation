/* FIPS 203, Section 6: ML-KEM
 *  Internal (deterministic) algorithms 16-18, external algorithms 19-21.
 */
#ifndef MLKEM_H
#define MLKEM_H
#include "params.h"

/* Alg 16 / 17 / 18: take explicit randomness, used for KAT testing */
void mlkem_keygen_internal(const mlkem_params *p, uint8_t *ek, uint8_t *dk,
                           const uint8_t d[32], const uint8_t z[32]);
void mlkem_encaps_internal(const mlkem_params *p, uint8_t K[32], uint8_t *c,
                           const uint8_t *ek, const uint8_t m[32]);
void mlkem_decaps_internal(const mlkem_params *p, uint8_t K[32], const uint8_t *dk, const uint8_t *c);

/* Alg 19 / 20 / 21: draw randomness from the OS and perform FIPS 203 input checks.
 * Return 0 on success, negative on failure. */
int mlkem_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk);
int mlkem_encaps(const mlkem_params *p, uint8_t K[32], uint8_t *c, const uint8_t *ek);
int mlkem_decaps(const mlkem_params *p, uint8_t K[32], const uint8_t *dk, const uint8_t *c);

/* Input checks (FIPS 203 Section 7.2 and 7.3) */
int mlkem_check_ek(const mlkem_params *p, const uint8_t *ek);   /* modulus check */
int mlkem_check_dk(const mlkem_params *p, const uint8_t *dk);   /* hash check    */

#endif
