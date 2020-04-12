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


unsigned char * Ganja_core(unsigned char * data, uint64_t datalen, unsigned char * D, unsigned char * salt, int saltlen) {
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
    uint64_t blocks = 0; 
    blocks = datalen / 32;
    int blocks_extra = datalen % 32;
    int blocksize = 32;
    if (blocks_extra != 0) {
        blocks += 1;
    }
    s = 0;
    m = 0x00000001;
    for (i = 0; i < (saltlen / 4); i++) {
        W[i] ^= (salt[s] << 24) + (salt[s+1] << 16) + (salt[s+2] << 8) + salt[s+3];
        W[i] = (W[i] + m) & 0xFFFFFFFF;
        s += 4;
    }
    int extra = blocks_extra % 4;
    int extc = (blocks_extra /4) % 8;
    int l = 4;
    int bc = 0;
    for (b = 0; b < blocks; b++) {
	for (i = 0; i < (blocksize / 4); i++) {
	    uint32_t block[8] = {blocks_extra};
            unsigned char temp[4] = {0};
	    if (b == (blocks - 1) && (blocks_extra != 0)) {
                if (bc > extc) {
		    for (f = 0; f < 4; f++) {
		        temp[f] =  0;
		        c += 1;
		    }
                    block[i] = conv8to32(temp);
                    H[i] ^= block[i] ^ W[i];
		}
		else if (bc <= extc) {
	            if (bc == extc) {
		        l = extra;
		    }
                    for (f = 0; f < l; f++) {
	                temp[f] = data[c];
	                c += 1;
	            }
                    block[i] = conv8to32(temp);
                    H[i] ^= block[i] ^ W[i];
		}
		s += 1;
            }
	    else {
                for (f = 0; f < 4; f++) {
	            temp[f] = data[c];
	            c += 1;
	        }
                block[i] = conv8to32(temp);
                H[i] ^= block[i] ^ W[i];
	    }
	}
        memcpy(temp32, H, 8 * sizeof(uint32_t));
	for (r = 0; r < rounds; r++) {
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
	}
        for (s = 0; s < 8; s++) {
            H[s] = (temp32[s] + H[s]) & 0xFFFFFFFF;
        }
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

unsigned char * Ganja_digest(unsigned char * data, long datalen, unsigned char * D, unsigned char * salt, int saltlen) {
    long blocklen = 256;
    if (datalen < blocklen) {
        unsigned char * block[blocklen];
        memset(block, 0, blocklen);
        int i;
        for (i = 0; i < datalen; i++) {
            block[i] = (uintptr_t)block[i] ^ data[i];
        }
        Ganja_core(block, blocklen, D, salt, saltlen);
    }
    else {
        Ganja_core(data, datalen, D, salt, saltlen);
    }
}
