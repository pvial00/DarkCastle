#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int SR0[80] = {
41, 26, 21, 17, 26, 10, 35, 20, 10, 9, 32, 33, 40, 43, 9, 36, 6, 29, 2, 26, 38, 32, 54, 8, 15, 34, 6, 34, 0, 55, 17, 16, 41, 43, 10, 50, 36, 49, 14, 2, 33, 23, 30, 36, 33, 36, 12, 8, 9, 2, 37, 35, 4, 36, 51, 39, 42, 40, 6, 45, 13, 48, 19, 27, 22, 24, 37, 49, 14, 17, 26, 35, 36, 25, 48, 41, 54, 53, 21, 15
};

int SR1[80] = {
19, 36, 43, 9, 30, 20, 49, 28, 8, 10, 48, 14, 15, 10, 9, 14, 35, 38, 24, 13, 26, 15, 12, 52, 4, 21, 39, 11, 4, 25, 33, 47, 52, 2, 36, 25, 20, 50, 40, 46, 19, 20, 20, 34, 26, 20, 9, 33, 24, 0, 19, 53, 26, 40, 10, 8, 34, 27, 40, 10, 23, 30, 13, 42, 46, 22, 32, 27, 53, 23, 28, 19, 35, 24, 30, 30, 45, 33, 38, 42
};

int SR2[80] = {
13, 36, 49, 8, 17, 37, 9, 20, 15, 26, 13, 37, 2, 31, 45, 22, 6, 55, 14, 38, 27, 22, 31, 50, 26, 40, 27, 44, 29, 44, 24, 21, 40, 36, 40, 48, 37, 25, 24, 26, 37, 43, 31, 11, 51, 46, 30, 39, 20, 27, 47, 43, 48, 37, 37, 44, 14, 22, 29, 54, 32, 33, 38, 2, 49, 17, 12, 8, 17, 54, 6, 40, 24, 20, 8, 55, 16, 10, 16, 18
};

int SR3[80] = {
36, 14, 39, 47, 27, 12, 41, 37, 24, 50, 53, 55, 20, 37, 19, 43, 9, 12, 34, 32, 29, 16, 47, 20, 14, 16, 10, 51, 53, 54, 10, 6, 0, 28, 25, 33, 23, 2, 14, 33, 38, 0, 51, 6, 6, 11, 46, 37, 4, 17, 16, 28, 15, 54, 28, 22, 9, 28, 49, 4, 53, 41, 28, 44, 4, 34, 10, 33, 17, 40, 9, 2, 12, 54, 42, 33, 34, 21, 25, 48
};


struct specjal_state {
    uint64_t Ka[80];
    uint64_t Kb[80];
    uint64_t Kc[80];
    uint64_t Kd[80];
    uint64_t d[80][4];
    int rounds;
};

struct specjal_ksa_state {
     uint64_t r[8];
     uint64_t j;
     uint64_t o;
};


uint64_t specjal_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t specjal_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void Suvajda_F(struct specjal_ksa_state *state) {
    int i;
    uint64_t x;
    uint64_t y[8];
    uint64_t o;
    for (i = 0; i < 8; i++) {
        y[i] = state->r[i]; 
    }   
    for (i = 0; i < 8; i++) {
        x = state->r[i];
        state->r[i] = (state->r[i] + state->r[(i + 1) & 0x07] + state->j);
        state->r[i] = state->r[i] ^ x;
        state->r[i] = specjal_rotl(state->r[i], 9);
        state->j = (state->j + state->r[i]);
    }   
    for (i = 0; i < 8; i++) {
        state->r[i] = state->r[i] + y[i];
    }   
    state->o = 0;
    state->o = (((((((state->r[0] + state->r[6]) ^ state->r[1]) + state->r[5]) ^ state->r[2]) + state->r[4]) ^ state->r[3]) + state->r[7]);
}


void SroundF(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb) {
    uint64_t a, b, c, d, temp;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = 0; r < state->rounds; r++) {
        a = specjal_rotr(a, SR0[r]);
        a += d;
        a ^= state->Ka[r];
        b = specjal_rotr(b, SR1[r]);
        b += c;
        b ^= state->Kb[r];
        c = specjal_rotl(c, SR2[r]);
        c += b;
        c ^= state->Kc[r];
        d = specjal_rotl(d, SR3[r]);
        d += a;
        d ^= state->Kd[r];
        a += b;
        b += a;
        c += d;
        d += c;

        a += state->d[r][0];
        b += state->d[r][1];
        c += state->d[r][2];
        d += state->d[r][3];
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void SroundB(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb) {
    uint64_t a, b, c, d, temp;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = state->rounds; r --> 0;) {
        d -= state->d[r][3];
        c -= state->d[r][2];
        b -= state->d[r][1];
        a -= state->d[r][0];

        d -= c;
        c -= d;
        b -= a;
        a -= b;
        d ^= state->Kd[r];
        d -= a;
        d = specjal_rotr(d, SR3[r]);
        c ^= state->Kc[r];
        c -= b;
        c = specjal_rotr(c, SR2[r]);
        b ^= state->Kb[r];
        b -= c;
        b = specjal_rotl(b, SR1[r]);
        a ^= state->Ka[r];
        a -= d;
        a = specjal_rotl(a, SR0[r]);
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void specjal_ksa(struct specjal_state *state, unsigned char * key, int keylen) {
    struct specjal_ksa_state kstate;
    int m = 0;
    int b;
    int inc = keylen / 8;
    int step = 8;
    state->rounds = (keylen / 8) + 64;
    memset(kstate.r, 0, 8*sizeof(uint64_t));
    memset(state->Ka, 0, state->rounds*sizeof(uint64_t));
    memset(state->Kb, 0, state->rounds*sizeof(uint64_t));
    memset(state->Kc, 0, state->rounds*sizeof(uint64_t));
    memset(state->Kd, 0, state->rounds*sizeof(uint64_t));
    memset(state->d, 0, 4*(state->rounds*sizeof(uint64_t)));
    kstate.j = 0;
    for (int i = 0; i < inc; i++) {
        kstate.r[i] = 0;
        kstate.r[i] = ((uint64_t)key[m] << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += step;
    }
    for (int i = 0; i < 8; i++) {
        kstate.j = (kstate.j + kstate.r[i]);
    }
    
    int c = 0;
    for (int r = 0; r < state->rounds; r++) {
        Suvajda_F(&kstate);
        state->Ka[r] ^= (uint64_t)kstate.o;
        Suvajda_F(&kstate);
        state->Kb[r] ^= (uint64_t)kstate.o;
        Suvajda_F(&kstate);
        state->Kc[r] ^= (uint64_t)kstate.o;
        Suvajda_F(&kstate);
        state->Kd[r] ^= (uint64_t)kstate.o;
    }
    for (int r = 0; r < state->rounds; r++) {
        Suvajda_F(&kstate);
        state->d[r][0] ^= (uint64_t)kstate.o;
        Suvajda_F(&kstate);
        state->d[r][1] ^= (uint64_t)kstate.o;
        Suvajda_F(&kstate);
        state->d[r][2] ^= (uint64_t)kstate.o;
        Suvajda_F(&kstate);
        state->d[r][3] ^= (uint64_t)kstate.o;
    }

}

void * specjal_cbc_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    int blocksize = 32;
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

    uint64_t block[4];
    uint64_t last[4];
    uint64_t next[4];
    struct specjal_state state;
    uint64_t i;
    int c = 0;
    int m = 0;
    specjal_ksa(&state, keyprime, key_length);
    int x, b;
    int t = 0;
    int ii;
    long ctr = 0;
    long ctrtwo = 0;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    m = 0;
    for (int i = 0; i < 4; i++) {
        last[i] = ((uint64_t)(iv[m]) << 56) + ((uint64_t)iv[m+1] << 48) + ((uint64_t)iv[m+2] << 40) + ((uint64_t)iv[m+3] << 32) + ((uint64_t)iv[m+4] << 24) + ((uint64_t)iv[m+5] << 16) + ((uint64_t)iv[m+6] << 8) + (uint64_t)iv[m+7];
        m += 8;
    }
    for (i = 0; i < (blocks); i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if (((i == (blocks - 1)) && (extra != 0))) {
            for (int p = 0; p < extrabytes; p++) {
                buffer[(bufsize+extrabytes-1)-p] = (unsigned char *)extrabytes;
            }
            bufsize = bufsize + extrabytes;
        }
        int bblocks = bufsize / 32;
        int bextra = bufsize % 32;
        if (bextra != 0) {
            bblocks += 1;
        }
        for (b = 0; b < bblocks; b++) {
            block[0] = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
            block[1] = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
            block[2] = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
            block[3] = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
            for (int r = 0; r < 4; r++) {
                block[r] = block[r] ^ last[r];
            }
            SroundF(&state, &block[0], &block[1], &block[2], &block[3]);
            for (int r = 0; r < 4; r++) {
                last[r] = block[r];
            }
            buffer[c] = (block[0] & 0xFF00000000000000) >> 56;
            buffer[c+1] = (block[0] & 0x00FF000000000000) >> 48;
            buffer[c+2] = (block[0] & 0x0000FF0000000000) >> 40;
            buffer[c+3] = (block[0] & 0x000000FF00000000) >> 32;
            buffer[c+4] = (block[0] & 0x00000000FF000000) >> 24;
            buffer[c+5] = (block[0] & 0x0000000000FF0000) >> 16;
            buffer[c+6] = (block[0] & 0x000000000000FF00) >> 8;
            buffer[c+7] = (block[0] & 0x00000000000000FF);
            buffer[c+8] = (block[1] & 0xFF00000000000000) >> 56;
            buffer[c+9] = (block[1] & 0x00FF000000000000) >> 48;
            buffer[c+10] = (block[1] & 0x0000FF0000000000) >> 40;
            buffer[c+11] = (block[1] & 0x000000FF00000000) >> 32;
            buffer[c+12] = (block[1] & 0x00000000FF000000) >> 24;
            buffer[c+13] = (block[1] & 0x0000000000FF0000) >> 16;
            buffer[c+14] = (block[1] & 0x000000000000FF00) >> 8;
            buffer[c+15] = (block[1] & 0x00000000000000FF);
            buffer[c+16] = (block[2] & 0xFF00000000000000) >> 56;
            buffer[c+17] = (block[2] & 0x00FF000000000000) >> 48;
            buffer[c+18] = (block[2] & 0x0000FF0000000000) >> 40;
            buffer[c+19] = (block[2] & 0x000000FF00000000) >> 32;
            buffer[c+20] = (block[2] & 0x00000000FF000000) >> 24;
            buffer[c+21] = (block[2] & 0x0000000000FF0000) >> 16;
            buffer[c+22] = (block[2] & 0x000000000000FF00) >> 8;
            buffer[c+23] = (block[2] & 0x00000000000000FF);
            buffer[c+24] = (block[3] & 0xFF00000000000000) >> 56;
            buffer[c+25] = (block[3] & 0x00FF000000000000) >> 48;
            buffer[c+26] = (block[3] & 0x0000FF0000000000) >> 40;
            buffer[c+27] = (block[3] & 0x000000FF00000000) >> 32;
            buffer[c+28] = (block[3] & 0x00000000FF000000) >> 24;
            buffer[c+29] = (block[3] & 0x0000000000FF0000) >> 16;
            buffer[c+30] = (block[3] & 0x000000000000FF00) >> 8;
            buffer[c+31] = (block[3] & 0x00000000000000FF);
            c += 32;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * specjal_cbc_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
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
    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    uint64_t block[4];
    uint64_t last[4];
    uint64_t next[4];
    struct specjal_state state;
    int iv_length = 32;
    int c = 0;
    int m = 0;
    specjal_ksa(&state, keyprime, key_length);
    int v = 32;
    uint64_t i;
    int x, b, r;
    int t = 0;
    int ctr = 0;
    int ctrtwo = 0;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        c = 0;

        m = 0;
        for (int i = 0; i < 4; i++) {
            last[i] = ((uint64_t)(iv[m]) << 56) + ((uint64_t)iv[m+1] << 48) + ((uint64_t)iv[m+2] << 40) + ((uint64_t)iv[m+3] << 32) + ((uint64_t)iv[m+4] << 24) + ((uint64_t)iv[m+5] << 16) + ((uint64_t)iv[m+6] << 8) + (uint64_t)iv[m+7];
            m += 8;
        }
        for (i = 0; i < (blocks); i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / 32;
            int bextra = bufsize % 32;
            if (bextra != 0) {
                bblocks += 1;
            }
            for (b = 0; b < bblocks; b++) {
                block[0] = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
                block[1] = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
                block[2] = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
                block[3] = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
                for (int r = 0; r < 4; r++) {
                    next[r] = block[r];
                }
                SroundB(&state, &block[0], &block[1], &block[2], &block[3]);
                for (int r = 0; r < 4; r++) {
                    block[r] = block[r] ^ last[r];
                    last[r] = next[r];
                }
                buffer[c] = (block[0] & 0xFF00000000000000) >> 56;
                buffer[c+1] = (block[0] & 0x00FF000000000000) >> 48;
                buffer[c+2] = (block[0] & 0x0000FF0000000000) >> 40;
                buffer[c+3] = (block[0] & 0x000000FF00000000) >> 32;
                buffer[c+4] = (block[0] & 0x00000000FF000000) >> 24;
                buffer[c+5] = (block[0] & 0x0000000000FF0000) >> 16;
                buffer[c+6] = (block[0] & 0x000000000000FF00) >> 8;
                buffer[c+7] = (block[0] & 0x00000000000000FF);
                buffer[c+8] = (block[1] & 0xFF00000000000000) >> 56;
                buffer[c+9] = (block[1] & 0x00FF000000000000) >> 48;
                buffer[c+10] = (block[1] & 0x0000FF0000000000) >> 40;
                buffer[c+11] = (block[1] & 0x000000FF00000000) >> 32;
                buffer[c+12] = (block[1] & 0x00000000FF000000) >> 24;
                buffer[c+13] = (block[1] & 0x0000000000FF0000) >> 16;
                buffer[c+14] = (block[1] & 0x000000000000FF00) >> 8;
                buffer[c+15] = (block[1] & 0x00000000000000FF);
                buffer[c+16] = (block[2] & 0xFF00000000000000) >> 56;
                buffer[c+17] = (block[2] & 0x00FF000000000000) >> 48;
                buffer[c+18] = (block[2] & 0x0000FF0000000000) >> 40;
                buffer[c+19] = (block[2] & 0x000000FF00000000) >> 32;
                buffer[c+20] = (block[2] & 0x00000000FF000000) >> 24;
                buffer[c+21] = (block[2] & 0x0000000000FF0000) >> 16;
                buffer[c+22] = (block[2] & 0x000000000000FF00) >> 8;
                buffer[c+23] = (block[2] & 0x00000000000000FF);
                buffer[c+24] = (block[3] & 0xFF00000000000000) >> 56;
                buffer[c+25] = (block[3] & 0x00FF000000000000) >> 48;
                buffer[c+26] = (block[3] & 0x0000FF0000000000) >> 40;
                buffer[c+27] = (block[3] & 0x000000FF00000000) >> 32;
                buffer[c+28] = (block[3] & 0x00000000FF000000) >> 24;
                buffer[c+29] = (block[3] & 0x0000000000FF0000) >> 16;
                buffer[c+30] = (block[3] & 0x000000000000FF00) >> 8;
                buffer[c+31] = (block[3] & 0x00000000000000FF);
                c += 32;
            }
            if (i == (blocks-1)) {
               int count = 0;
               int padcheck = buffer[(bufsize - 1)];
               int g = bufsize - 1;
               for (int m = 0; m < padcheck; m++) {
                   if ((int)buffer[g] == padcheck) {
                       count += 1;
                   }
                   g = (g - 1);
               }
               if (count == padcheck) {
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

