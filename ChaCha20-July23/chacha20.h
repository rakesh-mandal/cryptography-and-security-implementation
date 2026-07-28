#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE      32      /* 256-bit key */
#define CHACHA20_NONCE_SIZE    12      /* 96-bit nonce */
#define CHACHA20_BLOCK_SIZE    64      /* 64-byte keystream block */
#define CHACHA20_STATE_WORDS   16      /* 16 words = 512 bits */
#define CHACHA20_ROUNDS        20      /* 20 rounds */


void chacha20_block(
    uint8_t output[CHACHA20_BLOCK_SIZE],
    const uint8_t key[CHACHA20_KEY_SIZE],
    uint32_t counter,
    const uint8_t nonce[CHACHA20_NONCE_SIZE]
);

void chacha20_encrypt(
    uint8_t *output,
    const uint8_t *input,
    size_t length,
    const uint8_t key[CHACHA20_KEY_SIZE],
    uint32_t counter,
    const uint8_t nonce[CHACHA20_NONCE_SIZE]
);

#endif 

