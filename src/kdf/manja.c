#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct half_state {
    uint64_t r[16];
    uint64_t j;
};

uint64_t rotl64(uint64_t v, int c) {
    return ((v << c) | (v >> (64 - c)));
}

void uvajdaM_F(struct half_state *s) {
    int i;
    uint64_t x;
    uint64_t y[16];
    for (i = 0; i < 16; i++) {
        y[i] = s->r[i];
    }
    for (i = 0; i < 16; i++) {
        x = s->r[i];
        s->r[i] = (s->r[i] + s->r[(i + 1) & 0x0F] + s->j);
        s->r[i] = s->r[i] ^ x;
        s->r[i] = rotl64(s->r[i], 9);
        s->j = (s->j + s->r[i]);
    }
    for (i = 0; i < 16; i++) {
        s->r[i] = s->r[i] ^ y[i];
    }
}

uint64_t conv8to64(unsigned char buf[]) {
    int i;
    uint64_t output;

    output = ((uint64_t)buf[0] << 56) + ((uint64_t)buf[1] << 48) + ((uint64_t)buf[2] << 40) + ((uint64_t)buf[3] << 32) + ((uint64_t)buf[4] << 24) + ((uint64_t)buf[5] << 16) + ((uint64_t)buf[6] << 8) + (uint64_t)buf[7];
    return output;
}

void * manja_kdf(unsigned char * data, int datalen, unsigned char * D, int dlen,  unsigned char * salt, int saltlen, int iterations) {
    int minkeylen = 8;
    int blocklen = 256;
    if (dlen < minkeylen) {
        exit(1);
    }
    else if (dlen > blocklen) {
        exit(1);
    }
    unsigned char btmp[blocklen];
    memset(btmp, 0, blocklen);
    int i;
    for (i = 0; i < datalen; i++) {
        btmp[i] = btmp[i] ^ data[i];
    }
    int rounds = 8 * 8;
    uint64_t H[16] = {0};
    uint64_t temp32[16] = {0};
    uint64_t t, m;
    uint64_t W[16];
    uint64_t j = 0;
    struct half_state state;
    state.j = 0;
    W[0] = 0xe3ca7032bded8546;
    W[1] = 0x57aca88f018acfa0;
    W[2] = 0xec8da2888f4b7b73;
    W[3] = 0x01a266051b1b0d99;
    W[4] = 0xd561efc3e84ef67f;
    W[5] = 0x097c26048d06d725;
    W[6] = 0xd5517c26187b86ac;
    W[7] = 0x9bed70d43266d7d9;
    W[8] = 0x69c7b4c60f82dde9;
    W[9] = 0x25f5aacec7df566a;
    W[10] = 0x8ed825fb2d791a9c;
    W[11] = 0x846ea1ee90909361;
    W[12] = 0xbae16639c0a641d2;
    W[13] = 0x470d38bc85b88382;
    W[14] = 0xb97a6124b44d233a;
    W[15] = 0x158389284c35ce2c;
    int b, f, s, r, it;
    int c = 0;
    int blocks = 1; 
    int blocks_extra = 0;
    int blocksize = 256;
    int drounds = dlen / 8;
    s = 0;
    m = 0x0000000000000001;
    // XOR the salt with the static words
    for (i = 0; i < (saltlen / 8); i++) {
        W[i] ^= (salt[s] << 56) + (salt[s+1] << 48) + (salt[s+2] << 40) + (salt[s+3] << 32) + (salt[s+4] << 24) + (salt[s+5] << 16) + (salt[s+6] << 8) + salt[s+7];
        W[i] = (W[i] + m) & 0xFFFFFFFF;
        s += 8;
    }
    // Load the 256 byte block
    for (b = 0; b < 2; b++) {
        uint64_t block[16] = {0};
        for (i = 0; i < 16; i++) {
            unsigned char temp[8] = {0};
            for (f = 0; f < 8; f++) {
                temp[f] = btmp[c];
                c += 1;
            }
            block[i] = conv8to64(temp);
            H[i] ^= block[i] ^ W[i];
        }
    }
    // Setup Uvajda state
    for (i = 0; i < 16; i++) {
        state.r[i] = 0;
        state.r[i] = state.r[i] ^ H[i];
        state.j = state.j + state.r[i];
    }
    // Run iterations through the modified Ganja hash function and Uvajda function
    for (it = 0; it < iterations; it++) {
        for (r = 0; r < rounds; r++) {
            memcpy(temp32, H, 16 * sizeof(uint64_t));
            H[0] = (H[0] + H[1]);
            H[1] = rotl64(H[1] ^ H[2], 2);
            H[2] = (H[2] + H[3]);
            H[3] = rotl64(H[3] ^ H[4], 5);
            H[4] = (H[4] + H[5]);
            H[5] = rotl64(H[5] ^ H[6], 7);
            H[6] = (H[6] + H[7]);
            H[7] = rotl64(H[7] ^ H[8], 12);
            H[8] = (H[8] + H[9]);
            H[9] = rotl64(H[9] ^ H[10], 3);
            H[10] = (H[10] + H[11]);
            H[11] = rotl64(H[11] ^ H[12], 9);
            H[12] = (H[12] + H[13]);
            H[13] = rotl64(H[13] ^ H[14], 11);
            H[14] = (H[14] + H[15]);
            H[15] = rotl64(H[15] ^ H[0], 6);
            for (s = 0; s < 16; s++) {
                t = H[s];
                H[s] = H[(s + 1) & 0x0F];
                H[(s + 1) & 0x0F] = t;
            }
            uvajdaM_F(&state);
            for (s = 0; s < 16; s++) {
                H[s] = state.r[s] ^ H[s];
            }
            for (s = 0; s < 16; s++) {
                H[s] = (temp32[s] + H[s]);
            }
        }
    }
	    
    c = 0;
    for (i = 0; i < drounds; i++) {
        D[c] = (H[i] & 0xFF00000000000000) >> 56;
        D[c+1] = (H[i] & 0x00FF000000000000) >> 48;
        D[c+2] = (H[i] & 0x0000FF0000000000) >> 40;
        D[c+3] = (H[i] & 0x000000FF00000000) >> 32;
        D[c+4] = (H[i] & 0x00000000FF000000) >> 24;
        D[c+5] = (H[i] & 0x0000000000FF0000) >> 16;
        D[c+6] = (H[i] & 0x000000000000FF00) >> 8;
        D[c+7] = (H[i] & 0x00000000000000FF);
	c += 8;
    }
}
