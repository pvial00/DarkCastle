#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct specjal_state {
    uint64_t Ka[80];
    uint64_t Kb[80];
    uint64_t Kc[80];
    uint64_t Kd[80];
    uint64_t C[80][4];
    uint64_t d[80][4];
    int rounds;
};

uint64_t specjal_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t specjal_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void SroundF(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb) {
    uint64_t a, b, c, d, temp;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = 0; r < state->rounds; r++) {
/* Confusion */
        a += state->C[r][0];
        b += state->C[r][1];
        c += state->C[r][2];
        d += state->C[r][3];

        a += d;
        a = specjal_rotl(a, 44);
        a ^= state->Ka[r];

        b += a;
        b = specjal_rotl(b, 26);
        b ^= state->Kb[r];
        
        c += b;
        c = specjal_rotl(c, 19);
        c ^= state->Kc[r];
        
        d += c;
        d = specjal_rotl(d, 33);
        d ^= state->Kd[r];

/* Diffusion */
        a += b;
        b += a;
        c += d;
        d += c;
        a += d;
        d += a;

        a += state->d[r][0];
        b += state->d[r][1];
        c += state->d[r][2];
        d += state->d[r][3];
        a ^= b;
        b += a;


/* Transposition  */
        temp = b;
        b = c;
        c = temp;
        temp = a;
        a = d;
        d = temp;
        temp = b;
        b = d;
        d = temp; 


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
/* Transposition */
        temp = b;
        b = d;
        d = temp;
        temp = a;
        a = d; 
        d = temp;
        temp = b;
        b = c;
        c = temp; 

/* Diffusion */
        b -= a;
        a ^= b;
        d -= state->d[r][3];
        c -= state->d[r][2];
        b -= state->d[r][1];
        a -= state->d[r][0];

        d -= a;
        a -= d;
        d -= c;
        c -= d;
        b -= a;
        a -= b;
/* Confusion */
        d ^= state->Kd[r];
        d = specjal_rotr(d, 33);
        d -= c;

        c ^= state->Kc[r];
        c = specjal_rotr(c, 19);
        c -= b;
  
        b ^= state->Kb[r];
        b = specjal_rotr(b, 26);
        b -= a;

        a ^= state->Ka[r];
        a = specjal_rotr(a, 44);
        a -= d;

        d -= state->C[r][3];
        c -= state->C[r][2];
        b -= state->C[r][1];
        a -= state->C[r][0];

    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void specjal_ksa(struct specjal_state *state, unsigned char * key, int keylen) {
    uint64_t temp = 0x00000001;
    struct specjal_state tempstate;
    int m = 0;
    int b;
    int inc = keylen / 8;
    int l = 16;
    int step = 8;
    uint64_t *k[16];
    state->rounds = (keylen / 8) + 64;
    memset(k, 0, 16*sizeof(uint64_t));
    memset(state->Ka, 0, state->rounds*sizeof(uint64_t));
    memset(state->Kb, 0, state->rounds*sizeof(uint64_t));
    memset(state->Kc, 0, state->rounds*sizeof(uint64_t));
    memset(state->Kd, 0, state->rounds*sizeof(uint64_t));
    memset(tempstate.Ka, 0, state->rounds*sizeof(uint64_t));
    memset(tempstate.Kb, 0, state->rounds*sizeof(uint64_t));
    memset(tempstate.Kc, 0, state->rounds*sizeof(uint64_t));
    memset(tempstate.Kd, 0, state->rounds*sizeof(uint64_t));
    memset(state->d, 0, 4*(state->rounds*sizeof(uint64_t)));
    memset(state->C, 0, 4*(state->rounds*sizeof(uint64_t)));
    memset(tempstate.d, 0, 4*(state->rounds*sizeof(uint64_t)));
    memset(tempstate.C, 0, 4*(state->rounds*sizeof(uint64_t)));
    for (int i = 0; i < inc; i++) {
        k[i] = 0;
        k[i] = ((uint64_t)key[m] << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += step;
    }
    
    int c = 0;
    for (int r = 0; r < state->rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            tempstate.Ka[r] ^= (uint64_t)k[x];
        }
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            tempstate.Kb[r] ^= (uint64_t)k[x];
        }
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            tempstate.Kc[r] ^= (uint64_t)k[x];
        }
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            tempstate.Kd[r] ^= (uint64_t)k[x];
        }
    }
    c = 0;
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < 4; i++) {
            SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
            SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
            SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
            SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
            state->d[r][i] = 0;
            for (int x = 0; x < 16; x++) {
	        tempstate.d[r][i] ^= (uint64_t)k[x];
            } 
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < 4; i++) {
            SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
            SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
            SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
            SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
            state->C[r][i] = 0;
            for (int x = 0; x < 16; x++) {
	        tempstate.C[r][i] ^= (uint64_t)k[x];
            } 
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            state->Ka[r] = state->Ka[r] ^ (uint64_t)k[x];
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            state->Kb[r] ^= (uint64_t)k[x];
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            state->Kc[r] ^= (uint64_t)k[x];
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
        for (int x = 0; x < 16; x++) {
            state->Kd[r] ^= (uint64_t)k[x];
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < 4; i++) {
            SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
            SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
            SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
            SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
            for (int x = 0; x < 16; x++) {
                state->d[r][i] = (uint64_t)k[x];
            }
        }
    }
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < 4; i++) {
            SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3]);
            SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7]);
            SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11]);
            SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15]);
            state->C[r][i] = 0;
            for (int x = 0; x < 16; x++) {
                state->C[r][i] = (uint64_t)k[x];
            }
        }
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
    int iv_length = 32;
    //int state->rounds = 1;
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

