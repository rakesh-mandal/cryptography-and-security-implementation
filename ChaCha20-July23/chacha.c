#include "chacha20.h"

#include <string.h>


//ChaCha20 Constants
 static const uint32_t CONSTANTS[4] =
{
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574    
};

//Rotate Left (32-bit)
static uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

//Read 4 bytes (Little Endian)
static inline uint32_t load32(const uint8_t *src)
{
    return ((uint32_t)src[0])       |
           ((uint32_t)src[1] << 8)  |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

//Write 4 bytes (Little Endian)
static inline void store32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value);
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

//ChaCha20 Quarter Round
#define QUARTER_ROUND(s, a, b, c, d) {      \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16); \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12); \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);  \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);  \
}
//ChaCha20 Block Function
void chacha20_block(
    uint8_t output[CHACHA20_BLOCK_SIZE],
    const uint8_t key[CHACHA20_KEY_SIZE],
    uint32_t counter,
    const uint8_t nonce[CHACHA20_NONCE_SIZE]
)
{
    uint32_t state[16];
    uint32_t x[16];
    /* Constants */
    memcpy(state, CONSTANTS, sizeof(CONSTANTS));

    
    /* Key */
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32(key + (i * 4));
    }

    /* Block Counter */
    state[12] = counter;

    /* Nonce */
    state[13] = load32(nonce + 0);
    state[14] = load32(nonce + 4);
    state[15] = load32(nonce + 8);

    /* Copy initial state to working state */
    memcpy(x, state, sizeof(state));
    for (int i = 0; i < CHACHA20_ROUNDS; i += 2) {
        /* Column Round */
        QUARTER_ROUND(x, 0, 4,  8, 12);
        QUARTER_ROUND(x, 1, 5,  9, 13);
        QUARTER_ROUND(x, 2, 6, 10, 14);
        QUARTER_ROUND(x, 3, 7, 11, 15);

        /* Diagonal Round */
        QUARTER_ROUND(x, 0, 5, 10, 15);
        QUARTER_ROUND(x, 1, 6, 11, 12);
        QUARTER_ROUND(x, 2, 7,  8, 13);
        QUARTER_ROUND(x, 3, 4,  9, 14);
    }

    /* Add initial state and serialize */
    for (int i = 0; i < 16; i++) {
        store32(output + (4 * i), x[i] + state[i]);
    }

}   

//haCha20 Encryption / Decryption
void chacha20_encrypt(
    uint8_t *output,
    const uint8_t *input,
    size_t length,
    const uint8_t key[CHACHA20_KEY_SIZE],
    uint32_t counter,
    const uint8_t nonce[CHACHA20_NONCE_SIZE]
)
{
    uint8_t keystream[CHACHA20_BLOCK_SIZE];

    size_t i;
    size_t block_size;

    while (length > 0)
    {
        /* Generate one 64-byte keystream block */
        chacha20_block(
            keystream,
            key,
            counter,
            nonce
        );

        /* Number of bytes to process */
        block_size = (length < CHACHA20_BLOCK_SIZE)
                     ? length
                     : CHACHA20_BLOCK_SIZE;

        /* XOR plaintext with keystream */
        for (i = 0; i < block_size; i++)
        {
            output[i] = input[i] ^ keystream[i];
        }

        /* Move to the next block */
        output += block_size;
        input += block_size;

        length -= block_size;

        /* Increment block counter */
        counter++;
    }
}


