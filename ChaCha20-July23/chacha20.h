#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE      32      /* 256-bit key */
#define CHACHA20_NONCE_SIZE    12      /* 96-bit nonce */
#define CHACHA20_BLOCK_SIZE    64      /* 64-byte keystream block */
#define CHACHA20_STATE_WORDS   16      /* 16 words = 512 bits */
#define CHACHA20_ROUNDS        20      /* 20 rounds */

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
void chacha20_block(
    u8 output[CHACHA20_BLOCK_SIZE],
    const u8 key[CHACHA20_KEY_SIZE],
    u32 counter,
    const u8 nonce[CHACHA20_NONCE_SIZE]
);

void chacha20_encrypt(
    u8 *output,
    const u8 *input,
    size_t length,
    const u8 key[CHACHA20_KEY_SIZE],
    u32 counter,
    const u8 nonce[CHACHA20_NONCE_SIZE]
);

#endif 

