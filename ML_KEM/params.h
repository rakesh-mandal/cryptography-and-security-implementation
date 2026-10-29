/* FIPS 203, Section 8 (Table 2): ML-KEM parameter sets */
#ifndef MLKEM_PARAMS_H
#define MLKEM_PARAMS_H
#include <stddef.h>
#include <stdint.h>

#define MLKEM_N        256
#define MLKEM_Q        3329
#define MLKEM_ZETA     17          /* primitive 256th root of unity mod q */
#define MLKEM_KMAX     4
#define MLKEM_SS_BYTES 32

/* Maximum sizes (ML-KEM-1024) for stack buffers */
#define MLKEM_EK_MAX   1568
#define MLKEM_DK_MAX   3168
#define MLKEM_CT_MAX   1568

typedef struct {
    const char *name;
    int k, eta1, eta2, du, dv;
} mlkem_params;

extern const mlkem_params MLKEM_512, MLKEM_768, MLKEM_1024;

static inline size_t mlkem_ek_bytes(const mlkem_params *p) { return 384 * (size_t)p->k + 32; }
static inline size_t mlkem_dk_bytes(const mlkem_params *p) { return 768 * (size_t)p->k + 96; }
static inline size_t mlkem_ct_bytes(const mlkem_params *p) { return 32 * ((size_t)p->du * p->k + p->dv); }

typedef uint16_t poly_t[MLKEM_N];   /* element of R_q or T_q, coefficients in [0,q) */

#endif
