#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct specjal_state {
    uint64_t Ka[80];
    uint64_t Kb[80];
    uint64_t Kc[80];
    uint64_t Kd[80];
    uint64_t d[80][4];
};

struct ksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t specjal_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t specjal_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void SroundF(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb, int rounds) {
    uint64_t a, b, c, d, temp;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = 0; r < rounds; r++) {
        a += b;
        a = specjal_rotl(a, 9);
        a ^= state->Ka[r];

        b += a;
        b = specjal_rotl(b, 14);
        b ^= state->Kb[r];
        
        c += d;
        c = specjal_rotl(c, 17);
        c ^= state->Kc[r];
        
        d += c;
        d = specjal_rotl(d, 36);
        d ^= state->Kd[r];

        a += state->d[r][0];
        b += state->d[r][1];
        c += state->d[r][2];
        d += state->d[r][3];

        temp = b;
        b = c;
        c = temp;
        temp = a;
        a = d;
        d = temp;
        
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void SroundB(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb, int rounds) {
    uint64_t a, b, c, d, temp;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = rounds; r --> 0;) {

        temp = b;
        b = c;
        c = temp;
        temp = a;
        a = d;
        d = temp;

        d -= state->d[r][3];
        c -= state->d[r][2];
        b -= state->d[r][1];
        a -= state->d[r][0];

        d ^= state->Kd[r];
        d = specjal_rotr(d, 36);
        d -= c;

        c ^= state->Kc[r];
        c = specjal_rotr(c, 17);
        c -= d;
  
        b ^= state->Kb[r];
        b = specjal_rotr(b, 14);
        b -= a;

        a ^= state->Ka[r];
        a = specjal_rotr(a, 9);
        a -= b;

    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void specjal_ksa(struct specjal_state *state, unsigned char * key, int keylen, int rounds) {
    uint64_t temp = 0x00000001;
    struct specjal_state tempstate;
    struct ksa_state kstate;
    int m = 0;
    int b;
    int inc = keylen / 8;
    int l = 16;
    int step = 8;
    uint64_t *k[16];
    memset(k, 0, 16*sizeof(uint64_t));
    memset(state->Ka, 0, rounds*sizeof(uint64_t));
    memset(state->Kb, 0, rounds*sizeof(uint64_t));
    memset(state->Kc, 0, rounds*sizeof(uint64_t));
    memset(state->Kd, 0, rounds*sizeof(uint64_t));
    memset(tempstate.Ka, 0, rounds*sizeof(uint64_t));
    memset(tempstate.Kb, 0, rounds*sizeof(uint64_t));
    memset(tempstate.Kc, 0, rounds*sizeof(uint64_t));
    memset(tempstate.Kd, 0, rounds*sizeof(uint64_t));
    memset(state->d, 0, 4*(rounds*sizeof(uint64_t)));
    memset(tempstate.d, 0, 4*(rounds*sizeof(uint64_t)));
    for (int i = 0; i < inc; i++) {
        k[i] = 0;
        k[i] = ((uint64_t)key[m] << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += step;
    }
    m = 0;
    for (int i = 0; i < inc; i++) {
        kstate.r[i] = 0;
        kstate.r[i] = ((uint64_t)key[m] << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += step;
    }
    
    int c = 0;
    for (int r = 0; r < rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3], rounds);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7], rounds);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11], rounds);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15], rounds);
        tempstate.Ka[r] = 0;
        tempstate.Kb[r] = 0;
        tempstate.Kc[r] = 0;
        tempstate.Kd[r] = 0;
        tempstate.Ka[r] = (uint64_t)k[0] ^ (uint64_t)k[4] ^ (uint64_t)k[8] ^ (uint64_t)k[12];
        tempstate.Kb[r] = (uint64_t)k[1] ^ (uint64_t)k[5] ^ (uint64_t)k[9] ^ (uint64_t)k[13];
        tempstate.Kc[r] = (uint64_t)k[2] ^ (uint64_t)k[6] ^ (uint64_t)k[10] ^ (uint64_t)k[14];
        tempstate.Kd[r] = (uint64_t)k[3] ^ (uint64_t)k[7] ^ (uint64_t)k[11] ^ (uint64_t)k[15];
    }
    c = 0;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 4; i++) {
            SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3], rounds);
            SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7], rounds);
            SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11], rounds);
            SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15], rounds);
            state->d[r][i] = 0;
            for (int x = 0; x < 16; x++) {
	        tempstate.d[r][i] ^= (uint64_t)k[i];
            }
        }
    }
    for (int r = 0; r < rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3], rounds);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7], rounds);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11], rounds);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15], rounds);
        for (int x = 0; x < 16; x++) {
            state->Ka[r] = state->Ka[r] ^ (uint64_t)k[x];
        }
    }
    for (int r = 0; r < rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3], rounds);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7], rounds);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11], rounds);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15], rounds);
        for (int x = 0; x < 16; x++) {
            state->Kb[r] ^= (uint64_t)k[x];
        }
    }
    for (int r = 0; r < rounds; r++) {
        SroundF(&tempstate, &k[0], &k[1], &k[2], &k[3], rounds);
        SroundF(&tempstate, &k[4], &k[5], &k[6], &k[7], rounds);
        SroundF(&tempstate, &k[8], &k[9], &k[10], &k[11], rounds);
        SroundF(&tempstate, &k[12], &k[13], &k[m+14], &k[15], rounds);
        state->d[r][0] = (uint64_t)k[0] ^ (uint64_t)k[4] ^ (uint64_t)k[8] ^ (uint64_t)k[12];
        state->d[r][1] = (uint64_t)k[1] ^ (uint64_t)k[5] ^ (uint64_t)k[9] ^ (uint64_t)k[13];
        state->d[r][2] = (uint64_t)k[2] ^ (uint64_t)k[6] ^ (uint64_t)k[10] ^ (uint64_t)k[14];
        state->d[r][3] = (uint64_t)k[3] ^ (uint64_t)k[7] ^ (uint64_t)k[11] ^ (uint64_t)k[15];
    }
}

void specjal_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    uint8_t k[32];
    uint64_t block[4];
    uint64_t last[4];
    uint64_t next[4];
    struct specjal_state state;
    int iv_length = 32;
    int rounds = (keylen / 8) + 64;
    int c = 0;
    int m = 0;
    specjal_ksa(&state, key, keylen, rounds);
    int v = 32;
    int x, i;
    int t = 0;
    int ii;
    long ctr = 0;
    long ctrtwo = 0;
    int blocks = msglen / 32;
    int msglen_extra = extrabytes;
    int padsize = msglen + msglen_extra;
    unsigned char data[v];
    if (extrabytes != 0) {
        blocks += 1;
    }
    m = 0;
    for (int i = 0; i < 4; i++) {
        last[i] = ((uint64_t)(iv[m]) << 56) + ((uint64_t)iv[m+1] << 48) + ((uint64_t)iv[m+2] << 40) + ((uint64_t)iv[m+3] << 32) + ((uint64_t)iv[m+4] << 24) + ((uint64_t)iv[m+5] << 16) + ((uint64_t)iv[m+6] << 8) + (uint64_t)iv[m+7];
        m += 8;
    }
    for (i = 0; i < (blocks); i++) {
        for (ii = 0; ii < v; ii++) {
            data[ii] = msg[ctr];
            ctr = ctr + 1;
        }
        if (i == (blocks - 1)) {
            int g = 31;
            for (int b = 0; b < msglen_extra; b++) {
                data[g] = msglen_extra;
	        g = (g - 1);
            }
        }
        m = 0;
        for (int x = 0; x < 4; x++) {
            block[x] = ((uint64_t)(data[m]) << 56) + ((uint64_t)data[m+1] << 48) + ((uint64_t)data[m+2] << 40) + ((uint64_t)data[m+3] << 32) + ((uint64_t)data[m+4] << 24) + ((uint64_t)data[m+5] << 16) + ((uint64_t)data[m+6] << 8) + (uint64_t)data[m+7];
            m += 8;
        }
        for (int r = 0; r < 4; r++) {
            block[r] = block[r] ^ last[r];
        }
        SroundF(&state, &block[0], &block[1], &block[2], &block[3], rounds);
        for (int r = 0; r < 4; r++) {
            last[r] = block[r];
        }
        k[0] = (block[0] & 0xFF00000000000000) >> 56;
        k[1] = (block[0] & 0x00FF000000000000) >> 48;
        k[2] = (block[0] & 0x0000FF0000000000) >> 40;
        k[3] = (block[0] & 0x000000FF00000000) >> 32;
        k[4] = (block[0] & 0x00000000FF000000) >> 24;
        k[5] = (block[0] & 0x0000000000FF0000) >> 16;
        k[6] = (block[0] & 0x000000000000FF00) >> 8;
        k[7] = (block[0] & 0x00000000000000FF);
        k[8] = (block[1] & 0xFF00000000000000) >> 56;
        k[9] = (block[1] & 0x00FF000000000000) >> 48;
        k[10] = (block[1] & 0x0000FF0000000000) >> 40;
        k[11] = (block[1] & 0x000000FF00000000) >> 32;
        k[12] = (block[1] & 0x00000000FF000000) >> 24;
        k[13] = (block[1] & 0x0000000000FF0000) >> 16;
        k[14] = (block[1] & 0x000000000000FF00) >> 8;
        k[15] = (block[1] & 0x00000000000000FF);
        k[16] = (block[2] & 0xFF00000000000000) >> 56;
        k[17] = (block[2] & 0x00FF000000000000) >> 48;
        k[18] = (block[2] & 0x0000FF0000000000) >> 40;
        k[19] = (block[2] & 0x000000FF00000000) >> 32;
        k[20] = (block[2] & 0x00000000FF000000) >> 24;
        k[21] = (block[2] & 0x0000000000FF0000) >> 16;
        k[22] = (block[2] & 0x000000000000FF00) >> 8;
        k[23] = (block[2] & 0x00000000000000FF);
        k[24] = (block[3] & 0xFF00000000000000) >> 56;
        k[25] = (block[3] & 0x00FF000000000000) >> 48;
        k[26] = (block[3] & 0x0000FF0000000000) >> 40;
        k[27] = (block[3] & 0x000000FF00000000) >> 32;
        k[28] = (block[3] & 0x00000000FF000000) >> 24;
        k[29] = (block[3] & 0x0000000000FF0000) >> 16;
        k[30] = (block[3] & 0x000000000000FF00) >> 8;
        k[31] = (block[3] & 0x00000000000000FF);
        for (ii = 0; ii < v; ii++) {
            msg[ctrtwo] = k[ii];
            ctrtwo = ctrtwo + 1;
        }
    }
}

int specjal_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    uint8_t k[32];
    uint64_t block[4];
    uint64_t last[4];
    uint64_t next[4];
    struct specjal_state state;
    int iv_length = 32;
    int rounds = (keylen / 8) + 64;
    int c = 0;
    int m = 0;
    specjal_ksa(&state, key, keylen, rounds);
    int v = 32;
    int x, i;
    int t = 0;
    int ctr = 0;
    int ctrtwo = 0;
    int ii;
    unsigned char data[v];
    int blocks = msglen / 32;
    int extra = 0;
    m = 0;
    for (int i = 0; i < 4; i++) {
        last[i] = ((uint64_t)(iv[m]) << 56) + ((uint64_t)iv[m+1] << 48) + ((uint64_t)iv[m+2] << 40) + ((uint64_t)iv[m+3] << 32) + ((uint64_t)iv[m+4] << 24) + ((uint64_t)iv[m+5] << 16) + ((uint64_t)iv[m+6] << 8) + (uint64_t)iv[m+7];
        m += 8;
    }
    for (i = 0; i < (blocks); i++) {
        for (ii = 0; ii < v; ii++) {
            data[ii] = msg[ctr];
            ctr = ctr + 1;
        }
        m = 0;
        for (int x = 0; x < 4; x++) {
            block[x] = ((uint64_t)(data[m]) << 56) + ((uint64_t)data[m+1] << 48) + ((uint64_t)data[m+2] << 40) + ((uint64_t)data[m+3] << 32) + ((uint64_t)data[m+4] << 24) + ((uint64_t)data[m+5] << 16) + ((uint64_t)data[m+6] << 8) + (uint64_t)data[m+7];
            m += 8;
        }
        for (int r = 0; r < 4; r++) {
            next[r] = block[r];
        }
        SroundB(&state, &block[0], &block[1], &block[2], &block[3], rounds);
        for (int r = 0; r < 4; r++) {
            block[r] = block[r] ^ last[r];
            last[r] = next[r];
        }
        k[0] = (block[0] & 0xFF00000000000000) >> 56;
        k[1] = (block[0] & 0x00FF000000000000) >> 48;
        k[2] = (block[0] & 0x0000FF0000000000) >> 40;
        k[3] = (block[0] & 0x000000FF00000000) >> 32;
        k[4] = (block[0] & 0x00000000FF000000) >> 24;
        k[5] = (block[0] & 0x0000000000FF0000) >> 16;
        k[6] = (block[0] & 0x000000000000FF00) >> 8;
        k[7] = (block[0] & 0x00000000000000FF);
        k[8] = (block[1] & 0xFF00000000000000) >> 56;
        k[9] = (block[1] & 0x00FF000000000000) >> 48;
        k[10] = (block[1] & 0x0000FF0000000000) >> 40;
        k[11] = (block[1] & 0x000000FF00000000) >> 32;
        k[12] = (block[1] & 0x00000000FF000000) >> 24;
        k[13] = (block[1] & 0x0000000000FF0000) >> 16;
        k[14] = (block[1] & 0x000000000000FF00) >> 8;
        k[15] = (block[1] & 0x00000000000000FF);
        k[16] = (block[2] & 0xFF00000000000000) >> 56;
        k[17] = (block[2] & 0x00FF000000000000) >> 48;
        k[18] = (block[2] & 0x0000FF0000000000) >> 40;
        k[19] = (block[2] & 0x000000FF00000000) >> 32;
        k[20] = (block[2] & 0x00000000FF000000) >> 24;
        k[21] = (block[2] & 0x0000000000FF0000) >> 16;
        k[22] = (block[2] & 0x000000000000FF00) >> 8;
        k[23] = (block[2] & 0x00000000000000FF);
        k[24] = (block[3] & 0xFF00000000000000) >> 56;
        k[25] = (block[3] & 0x00FF000000000000) >> 48;
        k[26] = (block[3] & 0x0000FF0000000000) >> 40;
        k[27] = (block[3] & 0x000000FF00000000) >> 32;
        k[28] = (block[3] & 0x00000000FF000000) >> 24;
        k[29] = (block[3] & 0x0000000000FF0000) >> 16;
        k[30] = (block[3] & 0x000000000000FF00) >> 8;
        k[31] = (block[3] & 0x00000000000000FF);
        for (ii = 0; ii < v; ii++) {
            msg[ctrtwo] = k[ii];
            ctrtwo = ctrtwo + 1;
        }
        if (i == (blocks-1)) {
           int count = 0;
           int padcheck = k[31];
           int g = 31;
           for (int m = 0; m < padcheck; m++) {
               if ((int)k[g] == padcheck) {
                   count += 1;
               }
               g = (g - 1);
           }
           if (count == padcheck) {
               return count;
           }
           return padcheck;
        }
    }
}
