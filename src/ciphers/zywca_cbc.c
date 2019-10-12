#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int zywcablocklen = 32;

int R0[80] = {
36, 24, 28, 28, 27, 12, 11, 23, 17, 36, 14, 4, 52, 28, 27, 47, 51, 9, 36, 14, 12, 35, 33, 34, 51, 12, 38, 15, 24, 25, 4, 14, 19, 32, 30, 32, 26, 36, 53, 21, 29, 27, 16, 12, 6, 54, 20, 2, 52, 30, 25, 53, 31, 29, 33, 34, 47, 37, 0, 23, 14, 54, 55, 12, 23, 31, 26, 8, 9, 18, 35, 19, 30, 35, 10, 54, 30, 26, 45, 22
};

int R1[80] = {
9, 47, 29, 34, 16, 23, 14, 44, 50, 17, 12, 46, 17, 26, 17, 51, 4, 43, 26, 9, 18, 13, 27, 29, 54, 53, 39, 45, 12, 12, 25, 10, 42, 22, 8, 9, 19, 50, 39, 16, 16, 10, 48, 35, 33, 19, 20, 17, 15, 44, 53, 23, 45, 24, 40, 2, 27, 19, 16, 14, 20, 18, 27, 52, 38, 15, 50, 30, 31, 29, 28, 12, 18, 4, 37, 16, 33, 39, 14, 14
};

int R2[80] = {
34, 38, 15, 22, 49, 9, 44, 13, 18, 11, 33, 53, 30, 12, 22, 8, 54, 22, 47, 46, 47, 26, 27, 0, 21, 8, 36, 12, 32, 23, 32, 54, 20, 14, 41, 14, 11, 29, 55, 6, 28, 44, 19, 53, 14, 23, 11, 21, 54, 8, 51, 34, 25, 17, 43, 0, 17, 42, 30, 51, 39, 9, 18, 54, 38, 26, 32, 2, 55, 8, 45, 29, 25, 0, 41, 17, 34, 38, 55, 37
};

int R3[80] = {
26, 15, 50, 8, 39, 40, 9, 16, 42, 39, 50, 13, 15, 26, 37, 22, 22, 29, 23, 22, 9, 22, 54, 28, 17, 8, 52, 54, 45, 28, 11, 21, 48, 19, 28, 29, 41, 11, 20, 34, 40, 4, 8, 20, 29, 30, 28, 51, 16, 42, 4, 28, 29, 32, 37, 41, 41, 50, 6, 8, 47, 19, 55, 23, 8, 31, 40, 18, 51, 8, 23, 8, 33, 21, 48, 30, 27, 21, 22, 15
};

int R4[80] = {
54, 23, 45, 10, 24, 29, 11, 46, 0, 0, 49, 48, 43, 24, 8, 25, 4, 51, 8, 43, 50, 39, 15, 25, 14, 49, 39, 30, 8, 10, 27, 8, 47, 43, 12, 21, 28, 14, 36, 36, 38, 33, 38, 4, 30, 41, 8, 37, 10, 24, 6, 51, 30, 20, 9, 39, 48, 20, 51, 41, 8, 47, 11, 10, 21, 14, 18, 25, 21, 52, 41, 17, 47, 22, 6, 4, 29, 17, 33, 39
};

int R5[80] = {
43, 31, 49, 11, 8, 50, 10, 2, 54, 23, 42, 25, 9, 12, 43, 42, 46, 17, 14, 47, 37, 41, 37, 15, 8, 29, 40, 43, 24, 29, 16, 35, 8, 12, 17, 49, 28, 31, 0, 0, 14, 23, 23, 12, 24, 46, 21, 8, 43, 33, 8, 8, 15, 6, 44, 51, 17, 30, 52, 38, 38, 45, 54, 4, 54, 12, 9, 18, 27, 29, 55, 42, 37, 37, 12, 43, 28, 11, 13, 18
};

int R6[80] = {
47, 12, 36, 21, 35, 14, 15, 40, 22, 38, 38, 54, 8, 15, 12, 2, 19, 36, 32, 25, 32, 8, 40, 18, 47, 12, 45, 8, 15, 38, 40, 54, 26, 14, 12, 42, 8, 31, 52, 14, 36, 17, 16, 50, 37, 54, 52, 10, 40, 37, 12, 15, 17, 19, 16, 45, 12, 15, 14, 42, 39, 49, 48, 26, 19, 9, 20, 8, 37, 4, 9, 30, 8, 22, 36, 14, 12, 29, 22, 3
};

int R7[80] = {
15, 27, 39, 31, 14, 12, 10, 33, 16, 33, 45, 45, 22, 55, 45, 52, 49, 2, 23, 32, 24, 28, 52, 40, 55, 40, 36, 45, 2, 19, 10, 19, 16, 29, 11, 37, 34, 19, 9, 34, 27, 23, 48, 9, 13, 33, 38, 35, 51, 44, 23, 53, 30, 41, 50, 53, 8, 34, 42, 26, 38, 32, 28, 21, 43, 46, 15, 16, 28, 29, 44, 14, 35, 22, 8, 14, 20, 10, 8, 40
};

int R8[80] = {
14, 13, 10, 18, 2, 35, 8, 15, 47, 48, 36, 11, 14, 23, 50, 14, 39, 18, 31, 24, 29, 51, 48, 15, 37, 22, 41, 51, 10, 8, 43, 21, 12, 52, 34, 47, 34, 8, 10, 31, 46, 53, 42, 18, 34, 35, 8, 21, 16, 35, 40, 8, 52, 41, 14, 25, 18, 24, 8, 53, 32, 39, 13, 16, 4, 10, 18, 15, 19, 12, 44, 14, 45, 29, 22, 34, 30, 8, 52, 35
};

int R9[80] = {
26, 27, 34, 48, 27, 8, 9, 49, 24, 16, 35, 52, 14, 29, 38, 47, 11, 23, 19, 28, 2, 26, 33, 12, 2, 4, 15, 29, 30, 10, 25, 45, 18, 11, 44, 32, 2, 11, 10, 29, 12, 31, 32, 12, 19, 6, 49, 52, 14, 31, 11, 0, 21, 55, 23, 16, 29, 44, 9, 21, 10, 55, 24, 29, 6, 36, 33, 30, 17, 37, 10, 43, 43, 34, 24, 9, 19, 26, 16, 46
};

int R10[80] = {
20, 20, 43, 26, 10, 47, 6, 36, 27, 39, 12, 6, 49, 34, 36, 32, 22, 36, 55, 45, 42, 22, 45, 22, 27, 50, 27, 20, 10, 28, 9, 43, 53, 10, 44, 4, 20, 31, 47, 40, 32, 15, 55, 41, 14, 47, 30, 33, 20, 51, 40, 45, 28, 18, 18, 33, 27, 17, 50, 22, 35, 48, 20, 8, 48, 42, 48, 9, 8, 21, 6, 49, 6, 42, 22, 14, 26, 54, 41, 28
};

int R11[80] = {
20, 20, 43, 26, 10, 47, 6, 36, 27, 39, 12, 6, 49, 34, 36, 32, 22, 36, 55, 45, 42, 22, 45, 22, 27, 50, 27, 20, 10, 28, 9, 43, 53, 10, 44, 4, 20, 31, 47, 40, 32, 15, 55, 41, 14, 47, 30, 33, 20, 51, 40, 45, 28, 18, 18, 33, 27, 17, 50, 22, 35, 48, 20, 8, 48, 42, 48, 9, 8, 21, 6, 49, 6, 42, 22, 14, 26, 54, 41, 28
};


struct zywca_state {
    uint64_t C[80][4];
    uint64_t Ka[80];
    uint64_t Kb[80];
    uint64_t Kc[80];
    uint64_t Kd[80];
    uint64_t d[80][4];
    uint64_t last[4];
    uint64_t next[4];
    int rounds;
};

uint64_t zywca_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zywca_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void zywcagen_subkeys(struct zywca_state * state, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    int c = 0;
    int i;
    int s;
    uint64_t k[4];
    state->rounds = ((keylen / 4) + ((keylen / 8) + (48 - (keylen / 8))));
    memset(state->C, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->Ka, 0, state->rounds*(sizeof(uint64_t)));
    memset(state->Kb, 0, state->rounds*(sizeof(uint64_t)));
    memset(state->Kc, 0, state->rounds*(sizeof(uint64_t)));
    memset(state->Kd, 0, state->rounds*(sizeof(uint64_t)));
    memset(state->d, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->last, 0, 4*sizeof(uint64_t));
    memset(state->next, 0, 4*sizeof(uint64_t));

    for (i = 0; i < (keylen / 8); i++) {
        k[i] = ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    c = 0;
    for (i = 0; i < (ivlen / 8); i++) {
        state->last[i] = 0;
        state->last[i] = ((uint64_t)iv[c] << 56) + ((uint64_t)iv[c+1] << 48) + ((uint64_t)iv[c+2] << 40) + ((uint64_t)iv[c+3] << 32) + ((uint64_t)iv[c+4] << 24) + ((uint64_t)iv[c+5] << 16) + ((uint64_t)iv[c+6] << 8) + (uint64_t)iv[c+7];
	c += 8;
    }
    for (i = 0; i < state->rounds; i++) {
        k[0] = zywca_rotr(k[0], 8);
        k[0] += k[1]; 
        k[0] ^= k[2];
        k[1] = zywca_rotl(k[1], 3);
        k[1] += k[0];
        k[1] ^= k[3];
        k[2] = zywca_rotr(k[2], 9);
        k[2] += k[3];
        k[2] ^= k[0];
        k[3] = zywca_rotl(k[3], 4);
        k[3] += k[2];
        k[3] ^= k[1];
       for (s = 0; s < 4; s++) {
           state->Ka[i] ^= k[s];
        }
    }
    for (i = 0; i < state->rounds; i++) {
        k[0] = zywca_rotr(k[0], 8);
        k[0] += k[1];
        k[0] ^= k[2];
        k[1] = zywca_rotl(k[1], 3);
        k[1] += k[0];
        k[1] ^= k[3];
        k[2] = zywca_rotr(k[2], 9);
        k[2] += k[3];
        k[2] ^= k[0];
        k[3] = zywca_rotl(k[3], 4);
        k[3] += k[2];
        k[3] ^= k[1];
       for (s = 0; s < 4; s++) {
           state->Kb[i] ^= k[s];
        }
    }
    for (i = 0; i < state->rounds; i++) {
        k[0] = zywca_rotr(k[0], 8);
        k[0] += k[1];
        k[0] ^= k[2];
        k[1] = zywca_rotl(k[1], 3);
        k[1] += k[0];
        k[1] ^= k[3];
        k[2] = zywca_rotr(k[2], 9);
        k[2] += k[3];
        k[2] ^= k[0];
        k[3] = zywca_rotl(k[3], 4);
        k[3] += k[2];
        k[3] ^= k[1];
       for (s = 0; s < 4; s++) {
           state->Kc[i] ^= k[s];
        }
    }
    for (i = 0; i < state->rounds; i++) {
        k[0] = zywca_rotr(k[0], 8);
        k[0] += k[1];
        k[0] ^= k[2];
        k[1] = zywca_rotl(k[1], 3);
        k[1] += k[0];
        k[1] ^= k[3];
        k[2] = zywca_rotr(k[2], 9);
        k[2] += k[3];
        k[2] ^= k[0];
        k[3] = zywca_rotl(k[3], 4);
        k[3] += k[2];
        k[3] ^= k[1];
       for (s = 0; s < 4; s++) {
           state->Kd[i] ^= k[s];
        }
    }
    for (i = 0; i < state->rounds; i++) {
        k[0] = zywca_rotr(k[0], 8);
        k[0] += k[1];
        k[0] ^= k[2];
        k[1] = zywca_rotl(k[1], 3);
        k[1] += k[0];
        k[1] ^= k[3];
        k[2] = zywca_rotr(k[2], 9);
        k[2] += k[3];
        k[2] ^= k[0];
        k[3] = zywca_rotl(k[3], 4);
        k[3] += k[2];
        k[3] ^= k[1];
       for (s = 0; s < 4; s++) {
           state->C[i][s] = k[s];
        }
    }
    for (i = 0; i < state->rounds; i++) {
        k[0] = zywca_rotr(k[0], 8);
        k[0] += k[1];
        k[0] ^= k[2];
        k[1] = zywca_rotl(k[1], 3);
        k[1] += k[0];
        k[1] ^= k[3];
        k[2] = zywca_rotr(k[2], 9);
        k[2] += k[3];
        k[2] ^= k[0];
        k[3] = zywca_rotl(k[3], 4);
        k[3] += k[2];
        k[3] ^= k[1];
       for (s = 0; s < 4; s++) {
           state->d[i][s] = k[s];
        }
    }
}

uint64_t zywcablock_encrypt(struct zywca_state * state, uint64_t *xl, uint64_t *xr, uint64_t *xp, uint64_t *xq) {
    int r;
    uint64_t a, b, c, d, temp;

    a = *xl;
    b = *xr;
    c = *xp;
    d = *xq;

    for (r = 0; r < state->rounds; r++) {
/* Confusion */
        a += state->C[r][0];
        d += b;
        c = zywca_rotl(c, R0[r]) ^ a;

        b += state->C[r][1];
        c += a;
        d = zywca_rotl(d, R1[r]) ^ b;

        c += state->C[r][2];
        a += d;
        b = zywca_rotl(b, R2[r]) ^ c;

        d += state->C[r][3];
        b += a;
        a = zywca_rotl(a, R3[r]) ^ d;

        a ^= state->Ka[r];
        a = zywca_rotl(a, R4[r]);
        a += d;

        b ^= state->Kb[r];
        b = zywca_rotr(b, R5[r]);
        b += a;

        c ^= state->Kc[r];
        c = zywca_rotr(c, R6[r]);
        c += b;

        d ^= state->Kd[r];
        d = zywca_rotl(d, R7[r]);
        d += c;

/* Diffusion */
        d += state->d[r][3];
        c += b;
        a = zywca_rotl(a, R8[r]) ^ d;

        c += state->d[r][2];
        a += d;
        b = zywca_rotl(b, R9[r]) ^ c;

        b += state->d[r][1];
        d += a;
        c = zywca_rotl(c, R10[r]) ^ b;

        a += state->d[r][0];
        b += c;
        d = zywca_rotl(d, R11[r]) ^ a;

        a ^= d;
        b ^= a;
        c ^= b;
        d ^= c;

    }
    *xl = a;
    *xr = b;
    *xp = c; 
    *xq = d;

}

uint64_t zywcablock_decrypt(struct zywca_state * state, uint64_t *xl, uint64_t *xr, uint64_t *xp, uint64_t *xq) {
    int r;
    uint64_t a, b, c, d, temp;
    
    a = *xl;
    b = *xr;
    c = *xp;
    d = *xq;

    for (r = (state->rounds - 1); r != -1; r--) {
/* Diffusion */
        d ^= c;
        c ^= b;
        b ^= a;
        a ^= d;

        temp = d ^ a;
        d = zywca_rotr(temp, R11[r]);
        b -= c;
        a -= state->d[r][0];

        temp = c ^ b;
        c = zywca_rotr(temp, R10[r]);
        d -= a;
        b -= state->d[r][1];

        temp = b ^ c;
        b = zywca_rotr(temp, R9[r]);
        a -= d;
        c -= state->d[r][2];

        temp = a ^ d;
        a = zywca_rotr(temp, R8[r]);
        c -= b;
        d -= state->d[r][3];

/* Confusion */
        d -= c;
        d = zywca_rotr(d, R7[r]);
        d ^= state->Kd[r];

        c -= b;
        c = zywca_rotl(c, R6[r]);
        c ^= state->Kc[r];

        b -= a;
        b = zywca_rotl(b, R5[r]);
        b ^= state->Kb[r];

        a -= d;
        a = zywca_rotr(a, R4[r]);
        a ^= state->Ka[r];

        temp = a ^ d;
        a = zywca_rotr(temp, R3[r]);
        b -= a;
        d -= state->C[r][3];

        temp = b ^ c;
        b = zywca_rotr(temp, R2[r]);
        a -= d;
        c -= state->C[r][2];

        temp = d ^ b;
        d = zywca_rotr(temp, R1[r]);
        c -= a;
        b -= state->C[r][1];

        temp = c ^ a;
        c = zywca_rotr(temp, R0[r]);
        d -= b;
        a -= state->C[r][0];

    }
    *xl = a;
    *xr = b;
    *xp = c;
    *xq = d;
    
}

void * zywca_cbc_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    amagus_random(&iv, nonce_length);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(iv, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);

    struct zywca_state state;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocksize = 32;
    uint64_t blocks = datalen / bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    int extra = datalen % bufsize;
    int v = blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    int c = 0;
    int b;
    uint64_t i;
    zywcagen_subkeys(&state, keyprime, key_length, iv, nonce_length);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
	if ((i == (blocks - 1)) && (extra != 0)) {
            for (int p = 0; p < extrabytes; p++) {
                buffer[(bufsize+extrabytes-1)-p] = (unsigned char *)extrabytes;
	    }
            bufsize = bufsize + extrabytes;
	}
        int bblocks = bufsize / blocksize;
        int bextra = bufsize % blocksize;
        if (bextra != 0) {
            bblocks += 1;
        }
        if (bufsize < blocksize) {
            bblocks = 1;
        }
        for (b = 0; b < bblocks; b++) {
            xl = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
            xr = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
            xp = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
            xq = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
       
	    xl = xl ^ state.last[0];
	    xr = xr ^ state.last[1];
	    xp = xp ^ state.last[2];
	    xq = xq ^ state.last[3];

            zywcablock_encrypt(&state, &xl, &xr, &xp, &xq);

	    state.last[0] = xl;
	    state.last[1] = xr;
	    state.last[2] = xp;
	    state.last[3] = xq;
        
            buffer[c] = (xl & 0xFF00000000000000) >> 56;
            buffer[c+1] = (xl & 0x00FF000000000000) >> 48;
            buffer[c+2] = (xl & 0x0000FF0000000000) >> 40;
            buffer[c+3] = (xl & 0x000000FF00000000) >> 32;
            buffer[c+4] = (xl & 0x00000000FF000000) >> 24;
            buffer[c+5] = (xl & 0x0000000000FF0000) >> 16;
            buffer[c+6] = (xl & 0x000000000000FF00) >> 8;
            buffer[c+7] = (xl & 0x00000000000000FF);
            buffer[c+8] = (xr & 0xFF00000000000000) >> 56;
            buffer[c+9] = (xr & 0x00FF000000000000) >> 48;
            buffer[c+10] = (xr & 0x0000FF0000000000) >> 40;
            buffer[c+11] = (xr & 0x000000FF00000000) >> 32;
            buffer[c+12] = (xr & 0x00000000FF000000) >> 24;
            buffer[c+13] = (xr & 0x0000000000FF0000) >> 16;
            buffer[c+14] = (xr & 0x000000000000FF00) >> 8;
            buffer[c+15] = (xr & 0x00000000000000FF);
            buffer[c+16] = (xp & 0xFF00000000000000) >> 56;
            buffer[c+17] = (xp & 0x00FF000000000000) >> 48;
            buffer[c+18] = (xp & 0x0000FF0000000000) >> 40;
            buffer[c+19] = (xp & 0x000000FF00000000) >> 32;
            buffer[c+20] = (xp & 0x00000000FF000000) >> 24;
            buffer[c+21] = (xp & 0x0000000000FF0000) >> 16;
            buffer[c+22] = (xp & 0x000000000000FF00) >> 8;
            buffer[c+23] = (xp & 0x00000000000000FF);
            buffer[c+24] = (xq & 0xFF00000000000000) >> 56;
            buffer[c+25] = (xq & 0x00FF000000000000) >> 48;
            buffer[c+26] = (xq & 0x0000FF0000000000) >> 40;
            buffer[c+27] = (xq & 0x000000FF00000000) >> 32;
            buffer[c+28] = (xq & 0x00000000FF000000) >> 24;
            buffer[c+29] = (xq & 0x0000000000FF0000) >> 16;
            buffer[c+30] = (xq & 0x000000000000FF00) >> 8;
            buffer[c+31] = (xq & 0x00000000000000FF);
            c += 32;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    close(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * zywca_cbc_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen;
    int extrabytes = 32 - (datalen % 32);
    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    struct zywca_state state;
    int count = 0;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocksize = 32;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    int c = 0;
    int b;
    uint64_t i;
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        zywcagen_subkeys(&state, keyprime, key_length, iv, nonce_length);
        for (i = 0; i < blocks; i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / blocksize;
            int bextra = bufsize % blocksize;
            if (bextra != 0) {
                bblocks += 1;
            }
            for (b = 0; b < bblocks; b++) {
                xl = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
                xr = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
                xp = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
                xq = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
        
	        state.next[0] = xl;
	        state.next[1] = xr;
	        state.next[2] = xp;
	        state.next[3] = xq;

                zywcablock_decrypt(&state, &xl, &xr, &xp, &xq);
        
	        xl = xl ^ state.last[0];
	        xr = xr ^ state.last[1];
	        xp = xp ^ state.last[2];
	        xq = xq ^ state.last[3];
	        state.last[0] = state.next[0];
	        state.last[1] = state.next[1];
	        state.last[2] = state.next[2];
	        state.last[3] = state.next[3];
        
                buffer[c] = (xl & 0xFF00000000000000) >> 56;
                buffer[c+1] = (xl & 0x00FF000000000000) >> 48;
                buffer[c+2] = (xl & 0x0000FF0000000000) >> 40;
                buffer[c+3] = (xl & 0x000000FF00000000) >> 32;
                buffer[c+4] = (xl & 0x00000000FF000000) >> 24;
                buffer[c+5] = (xl & 0x0000000000FF0000) >> 16;
                buffer[c+6] = (xl & 0x000000000000FF00) >> 8;
                buffer[c+7] = (xl & 0x00000000000000FF);
                buffer[c+8] = (xr & 0xFF00000000000000) >> 56;
                buffer[c+9] = (xr & 0x00FF000000000000) >> 48;
                buffer[c+10] = (xr & 0x0000FF0000000000) >> 40;
                buffer[c+11] = (xr & 0x000000FF00000000) >> 32;
                buffer[c+12] = (xr & 0x00000000FF000000) >> 24;
                buffer[c+13] = (xr & 0x0000000000FF0000) >> 16;
                buffer[c+14] = (xr & 0x000000000000FF00) >> 8;
                buffer[c+15] = (xr & 0x00000000000000FF);
                buffer[c+16] = (xp & 0xFF00000000000000) >> 56;
                buffer[c+17] = (xp & 0x00FF000000000000) >> 48;
                buffer[c+18] = (xp & 0x0000FF0000000000) >> 40;
                buffer[c+19] = (xp & 0x000000FF00000000) >> 32;
                buffer[c+20] = (xp & 0x00000000FF000000) >> 24;
                buffer[c+21] = (xp & 0x0000000000FF0000) >> 16;
                buffer[c+22] = (xp & 0x000000000000FF00) >> 8;
                buffer[c+23] = (xp & 0x00000000000000FF);
                buffer[c+24] = (xq & 0xFF00000000000000) >> 56;
                buffer[c+25] = (xq & 0x00FF000000000000) >> 48;
                buffer[c+26] = (xq & 0x0000FF0000000000) >> 40;
                buffer[c+27] = (xq & 0x000000FF00000000) >> 32;
                buffer[c+28] = (xq & 0x00000000FF000000) >> 24;
                buffer[c+29] = (xq & 0x0000000000FF0000) >> 16;
                buffer[c+30] = (xq & 0x000000000000FF00) >> 8;
                buffer[c+31] = (xq & 0x00000000000000FF);
                c += 32;
            }

	    if (i == (blocks - 1)) {
	        int padcheck = buffer[bufsize - 1];
	        int g = bufsize - 1;
	        for (int p = 0; p < padcheck; p++) {
                    if ((int)buffer[g] == padcheck) {
                        count += 1;
		    }
		    g = g - 1;
                }
                if (padcheck == count) {
                    bufsize = bufsize - count;
                }
	    }
            fwrite(buffer, 1, bufsize, outfile);
        }
        fclose(infile);
        fclose(outfile);
    } 
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
