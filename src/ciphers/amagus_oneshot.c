#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int amagus1_rounds = 10;

struct amagus1_state {
    uint64_t r[16];
    int keylen;
};

uint64_t amagus1_rl(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t amagus1_rr(uint64_t a, uint64_t b) {
    return ((a >> b) | (a << (64 - b)));
}

void *amagus1_F(struct amagus1_state *state) {
    int r;
    for (r = 0; r < amagus1_rounds; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = amagus1_rl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = amagus1_rr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = amagus1_rl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = amagus1_rr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = amagus1_rl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];
        
        state->r[15] += state->r[6];
        state->r[2] ^= state->r[15];
        state->r[14] = amagus1_rl((state->r[14] ^ state->r[12]), 9);
        state->r[4] += state->r[9];
        state->r[13] ^= state->r[11];
        state->r[6] = amagus1_rr((state->r[6] ^ state->r[10]), 6);
        state->r[12] += state->r[13];
        state->r[8] ^= state->r[8];
        state->r[11] = amagus1_rl((state->r[11] ^ state->r[3]), 11);
        state->r[10] += state->r[1];
        state->r[1] ^= state->r[4];
        state->r[3] = amagus1_rr((state->r[3] ^ state->r[7]), 7);
        state->r[5] += state->r[0];
        state->r[7] ^= state->r[2];
        state->r[9] = amagus1_rl((state->r[9] ^ state->r[0]), 3);
        state->r[0] += state->r[5];
    }
}

void amagus1_keysetup(struct amagus1_state *state, unsigned char *key, unsigned char *nonce) {
    uint64_t n[2];
    int i;
    int m = 0;
    int inc = 8;
    memset(state->r, 0, (16*(sizeof(uint64_t))));
    for (i = 0; i < (state->keylen / 8); i++) {
        state->r[i] = 0;
        state->r[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }
  
    n[0] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    n[1] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    state->r[14] = state->r[0] ^ n[0];
    state->r[15] = state->r[1] ^ n[1];


    for (int i = 0; i < amagus1_rounds; i++) {
        amagus1_F(state);
    }
}

void * amagus1_crypt(unsigned char * data, unsigned char * key, int keylen, unsigned char * nonce, long datalen) {
    struct amagus1_state state;
    state.keylen = keylen;
    long c = 0;
    int i = 0;
    int l = 8;
    uint64_t output;
    int k[8] = {0};
    long blocks = datalen / 8;
    long extra = datalen % 8;
    if (extra != 0) {
        blocks += 1;
    }
    amagus1_keysetup(&state, key, nonce);
    for (long b = 0; b < blocks; b++) {
        amagus1_F(&state);
        output = (state.r[0] ^ state.r[1] ^ state.r[2] ^ state.r[3] ^ state.r[4] ^ state.r[5] ^ state.r[6] ^ state.r[5] ^ state.r[6] ^ state.r[7] ^ state.r[8] ^ state.r[9] ^ state.r[10] ^ state.r[11] ^ state.r[12] ^ state.r[13] ^ state.r[14] ^ state.r[15]);
        k[0] = (output & 0x00000000000000FF);
        k[1] = (output & 0x000000000000FF00) >> 8;
        k[2] = (output & 0x0000000000FF0000) >> 16;
        k[3] = (output & 0x00000000FF000000) >> 24;
        k[4] = (output & 0x000000FF00000000) >> 32;
        k[5] = (output & 0x0000FF0000000000) >> 40;
        k[6] = (output & 0x00FF000000000000) >> 48;
        k[7] = (output & 0xFF00000000000000) >> 56;
        if (b == (blocks - 1) && (extra != 0)) {
            l = extra;
        }

	for (i = 0; i < l; i++) {
            data[c] = data[c] ^ k[i];
            c += 1;
	}
    }
}

unsigned char * amagus_random (unsigned char *buf, int num_bytes) {
    int keylen = 128;
    int noncelen = 16;
    unsigned char *key[keylen];
    unsigned char *nonce[noncelen];
    FILE *randfile;
    randfile = fopen("/dev/urandom", "rb");
    fread(nonce, noncelen, 1, randfile);
    fread(key, keylen, 1, randfile);
    fclose(randfile);
    amagus1_crypt(buf, key, keylen, nonce, num_bytes);
}
