#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t Q[2] = {
0x3fcb3d9deac52511, 0x18a89dd6bb3c4d04
};

struct qapla_state {
     uint64_t r[8];
     uint64_t o[4];
     int rounds;
};

void qapla_F(struct qapla_state *state) {
    int i;
    uint64_t x;
    uint64_t y[8];
    for (i = 0; i < 8; i++) {
        y[i] = state->r[i];
    }
    for (i = 0; i < state->rounds; i++) {
        state->r[0] += state->r[4];
        state->r[1] = rotateleft64((state->r[1] ^ state->r[0]), 9);
        state->r[2] += state->r[5];
        state->r[3] = rotateleft64((state->r[3] ^ state->r[1]), 21);
        state->r[4] += state->r[6];
        state->r[5] = rotateleft64((state->r[5] ^ state->r[2]), 12);
        state->r[6] += state->r[7];
        state->r[7] = rotateleft64((state->r[7] ^ state->r[3]), 18);
        state->r[1] += state->r[4];
        state->r[2] = rotateleft64((state->r[2] ^ state->r[1]), 9);
        state->r[3] += state->r[5];
        state->r[4] = rotateleft64((state->r[4] ^ state->r[3]), 21);
        state->r[5] += state->r[6];
        state->r[6] = rotateleft64((state->r[6] ^ state->r[5]), 12);
        state->r[7] += state->r[7];
        state->r[0] = rotateleft64((state->r[0] ^ state->r[7]), 18);
    }
    for (i = 0; i < 8; i++) {
        state->r[i] = state->r[i] + y[i];
    }
    for (i = 0; i < 4; i++) {
        state->o[i] = state->r[i] ^ state->r[(i + 4) & 0x07];
    }

}

void qapla_keysetup(struct qapla_state *state, unsigned char *key, unsigned char *nonce) {
    memset(state->r, 0, 8*(sizeof(uint64_t)));
    int i;
    state->rounds = 12;
    state->r[0] = Q[0];
    state->r[4] = Q[1];
    state->r[1] = ((uint64_t)(key[0]) << 56) + ((uint64_t)key[1] << 48) + ((uint64_t)key[2] << 40) + ((uint64_t)key[3] << 32) + ((uint64_t)key[4] << 24) + ((uint64_t)key[5] << 16) + ((uint64_t)key[6] << 8) + (uint64_t)key[7];
    state->r[3] = ((uint64_t)(key[8]) << 56) + ((uint64_t)key[9] << 48) + ((uint64_t)key[10] << 40) + ((uint64_t)key[11] << 32) + ((uint64_t)key[12] << 24) + ((uint64_t)key[13] << 16) + ((uint64_t)key[14] << 8) + (uint64_t)key[15];
    state->r[2] = ((uint64_t)(key[16]) << 56) + ((uint64_t)key[17] << 48) + ((uint64_t)key[18] << 40) + ((uint64_t)key[19] << 32) + ((uint64_t)key[20] << 24) + ((uint64_t)key[21] << 16) + ((uint64_t)key[22] << 8) + (uint64_t)key[23];
    state->r[5] = ((uint64_t)(key[24]) << 56) + ((uint64_t)key[25] << 48) + ((uint64_t)key[26] << 40) + ((uint64_t)key[27] << 32) + ((uint64_t)key[28] << 24) + ((uint64_t)key[29] << 16) + ((uint64_t)key[30] << 8) + (uint64_t)key[31];

    state->r[6] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    state->r[7] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    for (i = 0; i < 64; i++) {
        qapla_F(state);
    }
}

void * qapla_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
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
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    struct qapla_state state;
    long c = 0;
    uint64_t i = 0;
    int l = 32;
    uint64_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    /*
    if (datalen < bufsize) {
        blocks = 1;
        bufsize = extra;
    } */
    qapla_keysetup(&state, keyprime, nonce);
    for (uint64_t b = 0; b < blocks; b++) {
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        for (i = 0; i < (bufsize / 32); i++) {
            qapla_F(&state);
            k[c] = (state.o[0] & 0x00000000000000FF);
            k[c+1] = (state.o[0] & 0x000000000000FF00) >> 8;
            k[c+2] = (state.o[0] & 0x0000000000FF0000) >> 16;
            k[c+3] = (state.o[0] & 0x00000000FF000000) >> 24;
            k[c+4] = (state.o[0] & 0x000000FF00000000) >> 32;
            k[c+5] = (state.o[0] & 0x0000FF0000000000) >> 40;
            k[c+6] = (state.o[0] & 0x00FF000000000000) >> 48;
            k[c+7] = (state.o[0] & 0xFF00000000000000) >> 56;
            k[c+8] = (state.o[1] & 0x00000000000000FF);
            k[c+9] = (state.o[1] & 0x000000000000FF00) >> 8;
            k[c+10] = (state.o[1] & 0x0000000000FF0000) >> 16;
            k[c+11] = (state.o[1] & 0x00000000FF000000) >> 24;
            k[c+12] = (state.o[1] & 0x000000FF00000000) >> 32;
            k[c+13] = (state.o[1] & 0x0000FF0000000000) >> 40;
            k[c+14] = (state.o[1] & 0x00FF000000000000) >> 48;
            k[c+15] = (state.o[1] & 0xFF00000000000000) >> 56;
            k[c+16] = (state.o[2] & 0x00000000000000FF);
            k[c+17] = (state.o[2] & 0x000000000000FF00) >> 8;
            k[c+18] = (state.o[2] & 0x0000000000FF0000) >> 16;
            k[c+19] = (state.o[2] & 0x00000000FF000000) >> 24;
            k[c+20] = (state.o[2] & 0x000000FF00000000) >> 32;
            k[c+21] = (state.o[2] & 0x0000FF0000000000) >> 40;
            k[c+22] = (state.o[2] & 0x00FF000000000000) >> 48;
            k[c+23] = (state.o[2] & 0xFF00000000000000) >> 56;
            k[c+24] = (state.o[3] & 0x00000000000000FF);
            k[c+25] = (state.o[3] & 0x000000000000FF00) >> 8;
            k[c+26] = (state.o[3] & 0x0000000000FF0000) >> 16;
            k[c+27] = (state.o[3] & 0x00000000FF000000) >> 24;
            k[c+28] = (state.o[3] & 0x000000FF00000000) >> 32;
            k[c+29] = (state.o[3] & 0x0000FF0000000000) >> 40;
            k[c+30] = (state.o[3] & 0x00FF000000000000) >> 48;
            k[c+31] = (state.o[3] & 0xFF00000000000000) >> 56;
            c += 32;
        }
        for (i = 0 ; i < bufsize; i++) {
            buffer[i] = buffer[i] ^ k[i];
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * qapla_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
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
    fread(nonce, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);
    struct qapla_state state;
    long c = 0;
    int i = 0;
    int l = 8;
    uint64_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        qapla_keysetup(&state, keyprime, nonce);
        for (uint64_t b = 0; b < blocks; b++) {
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            if ((b == (blocks - 1)) && (extra != 0)) {
                bufsize = extra;
            }
            for (i = 0; i < (bufsize / 32); i++) {
                qapla_F(&state);
                k[c] = (state.o[0] & 0x00000000000000FF);
                k[c+1] = (state.o[0] & 0x000000000000FF00) >> 8;
                k[c+2] = (state.o[0] & 0x0000000000FF0000) >> 16;
                k[c+3] = (state.o[0] & 0x00000000FF000000) >> 24;
                k[c+4] = (state.o[0] & 0x000000FF00000000) >> 32;
                k[c+5] = (state.o[0] & 0x0000FF0000000000) >> 40;
                k[c+6] = (state.o[0] & 0x00FF000000000000) >> 48;
                k[c+7] = (state.o[0] & 0xFF00000000000000) >> 56;
                k[c+8] = (state.o[1] & 0x00000000000000FF);
                k[c+9] = (state.o[1] & 0x000000000000FF00) >> 8;
                k[c+10] = (state.o[1] & 0x0000000000FF0000) >> 16;
                k[c+11] = (state.o[1] & 0x00000000FF000000) >> 24;
                k[c+12] = (state.o[1] & 0x000000FF00000000) >> 32;
                k[c+13] = (state.o[1] & 0x0000FF0000000000) >> 40;
                k[c+14] = (state.o[1] & 0x00FF000000000000) >> 48;
                k[c+15] = (state.o[1] & 0xFF00000000000000) >> 56;
                k[c+16] = (state.o[2] & 0x00000000000000FF);
                k[c+17] = (state.o[2] & 0x000000000000FF00) >> 8;
                k[c+18] = (state.o[2] & 0x0000000000FF0000) >> 16;
                k[c+19] = (state.o[2] & 0x00000000FF000000) >> 24;
                k[c+20] = (state.o[2] & 0x000000FF00000000) >> 32;
                k[c+21] = (state.o[2] & 0x0000FF0000000000) >> 40;
                k[c+22] = (state.o[2] & 0x00FF000000000000) >> 48;
                k[c+23] = (state.o[2] & 0xFF00000000000000) >> 56;
                k[c+24] = (state.o[3] & 0x00000000000000FF);
                k[c+25] = (state.o[3] & 0x000000000000FF00) >> 8;
                k[c+26] = (state.o[3] & 0x0000000000FF0000) >> 16;
                k[c+27] = (state.o[3] & 0x00000000FF000000) >> 24;
                k[c+28] = (state.o[3] & 0x000000FF00000000) >> 32;
                k[c+29] = (state.o[3] & 0x0000FF0000000000) >> 40;
                k[c+30] = (state.o[3] & 0x00FF000000000000) >> 48;
                k[c+31] = (state.o[3] & 0xFF00000000000000) >> 56;
                c += 32;
            }
            for (i = 0 ; i < bufsize; i++) {
                buffer[i] = buffer[i] ^ k[i];
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
