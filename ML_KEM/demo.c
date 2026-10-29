/* Minimal ML-KEM-768 example: receiver generates keys, sender encapsulates,
 * receiver decapsulates, both end up with the same 32-byte shared secret. */
#include <stdio.h>
#include <string.h>
#include "mlkem.h"

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    const mlkem_params *p = &MLKEM_768;
    uint8_t ek[MLKEM_EK_MAX], dk[MLKEM_DK_MAX], ct[MLKEM_CT_MAX];
    uint8_t K_sender[32], K_receiver[32];

    if (mlkem_keygen(p, ek, dk))                 { puts("keygen failed"); return 1; }  /* receiver */
    if (mlkem_encaps(p, K_sender, ct, ek))       { puts("encaps failed"); return 1; }  /* sender   */
    if (mlkem_decaps(p, K_receiver, dk, ct))     { puts("decaps failed"); return 1; }  /* receiver */

    printf("%s  ek=%zu dk=%zu ct=%zu bytes\n", p->name,
           mlkem_ek_bytes(p), mlkem_dk_bytes(p), mlkem_ct_bytes(p));
    print_hex("sender   K = ", K_sender, 32);
    print_hex("receiver K = ", K_receiver, 32);
    puts(memcmp(K_sender, K_receiver, 32) == 0 ? "MATCH" : "MISMATCH");
    return 0;
}
