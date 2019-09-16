#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
/*
uint32_t conv8to32(unsigned char buf[]) {
    int i;
    uint32_t output;

    output = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
    return output;
}

uint32_t rotl(uint32_t v, int c) {
    return ((v << c) | (v >> (32 - c)));
}
*/
void * ganja_hmac(unsigned char *data, long long datalen, unsigned char * D, unsigned char * key, int keylen) {
    int rounds = 8 * 8;
    uint32_t H[8] = {0};
    uint32_t temp32[8] = {0};
    uint32_t t, m;
    uint32_t W[8];
    W[0] = 0x72000000;
    W[1] = 0xacdef012;
    W[2] = 0x0059c491;
    W[3] = 0xb8a79b02;
    W[4] = 0x31ba94b9;
    W[5] = 0x45000057;
    W[6] = 0xb5f3810a;
    W[7] = 0x8a348b7d;
    int b, i, f, s, r;
    int c = 0;
    int blocks = 0; 
    blocks = datalen / 4;
    int blocks_extra = datalen % 4;
    int blocksize = 32;
    s = 0;
    m = 0x00000001;
    for (i = 0; i < (keylen / 4); i++) {
        W[i & 0x07] ^= (key[s] << 24) + (key[s+1] << 16) + (key[s+2] << 8) + key[s+3];
        H[i & 0x07] ^= (key[s] << 24) + (key[s+1] << 16) + (key[s+2] << 8) + key[s+3];
        W[i & 0x07] = (W[i & 0x07] + m + H[i & 0x07]) & 0xFFFFFFFF;
        s += 4;
    }
        
    s = 0;
    /*
    for (i = 0; i < (datalen / 4); i++) {
        H[i] ^= (data[s] << 24) + (data[s+1] << 16) + (data[s+2] << 8) + data[s+3];
        H[i] = (H[i] + m + W[i]) & 0xFFFFFFFF;
        s += 4;
    } */
    for (i = 0; i < (datalen); i++) {
        H[i & 0x07] ^= data[i];
        H[i & 0x07] = ((H[i & 0x07] + m + data[i]) & 0xFFFFFFFF) ^ W[i & 0x07];
        s += 4;
    }
    int l = 4;
    for (r = 0; r < rounds; r++) {
       memcpy(temp32, H, 8 * sizeof(uint32_t));
       H[0] = (H[0] + H[1]) & 0xFFFFFFFF;
       H[1] = rotl(H[1] ^ H[2], 2);
       H[2] = (H[2] + H[3]) & 0xFFFFFFFF;
       H[3] = rotl(H[3] ^ H[4], 5);
       H[4] = (H[4] + H[5]) & 0xFFFFFFFF;
       H[5] = rotl(H[5] ^ H[6], 7);
       H[6] = (H[6] + H[7]) & 0xFFFFFFFF;
       H[7] = rotl(H[7] ^ H[0], 12);
       for (s = 0; s < 7; s++) {
           t = H[s];
	   H[s] = H[(s + 1) & 0x07];
	   H[(s + 1) & 0x07] = t;
        }
        for (s = 0; s < 8; s++) {
            H[s] = (temp32[s] + H[s]) & 0xFFFFFFFF;
        }
    }

    for (s = 0; s < 8; s++) {
        H[s] ^= W[s];
    }

	    
    c = 0;
    for (i = 0; i < 8; i++) {
        D[c] = (H[i] & 0xFF000000) >> 24;
        D[c+1] = (H[i] & 0x00FF0000) >> 16;
        D[c+2] = (H[i] & 0x0000FF00) >> 8;
        D[c+3] = (H[i] & 0x000000FF);
	c = (c + 4);
    }
}
