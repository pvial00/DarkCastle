#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct uvajda1_state {
     uint64_t r[8];
     uint64_t j;
};

uint64_t rotateleft64(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

void uvajda1_F(struct uvajda1_state *state) {
    int i;
    uint64_t x;
    uint64_t y[8];
    for (i = 0; i < 8; i++) {
        y[i] = state->r[i];
    }
    for (i = 0; i < 8; i++) {
        x = state->r[i];
	state->r[i] = (state->r[i] + state->r[(i + 1) & 0x07] + state->j);
	state->r[i] = state->r[i] ^ x;
	state->r[i] = rotateleft64(state->r[i], 9);
	state->j = (state->j + state->r[i]);
    }
    for (i = 0; i < 8; i++) {
        state->r[i] = state->r[i] + y[i];
    }
}

void uvajda1_keysetup(struct uvajda1_state *state, unsigned char *key, unsigned char *nonce) {
    memset(state->r, 0, 8*(sizeof(uint64_t)));
    uint64_t n[4];
    int i;
    int m = 0;
    int inc = 8;
    for (i = 0; i < (32 / 8); i++) {
        state->r[i] = 0;
        state->r[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }
   
    n[0] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    n[1] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    state->r[0] = state->r[0] ^ n[0];
    state->r[1] = state->r[1] ^ n[1];

    state->j = 0;

    for (int i = 0; i < 8; i++) {
        state->j = (state->j + state->r[i]);
    }
    for (int i = 0; i < 2; i++) {
        uvajda1_F(state);
    }
    for (int i = 0; i < 8; i++) {
        state->j = (state->j + state->r[i]);
    }
    for (int i = 0; i < 62; i++) {
        uvajda1_F(state);
    }
}

void * uvajda1_crypt(unsigned char * data, unsigned char * key, unsigned char * nonce, long datalen) {
    struct uvajda1_state state;
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
    uvajda1_keysetup(&state, key, nonce);
    for (long b = 0; b < blocks; b++) {
        uvajda1_F(&state);
        output = (((((((state.r[0] + state.r[6]) ^ state.r[1]) + state.r[5]) ^ state.r[2]) + state.r[4]) ^ state.r[3]) + state.r[7]);
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
