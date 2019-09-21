#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct dark_state {
    uint32_t r[8];
    uint32_t j;
    uint32_t c;
};

uint32_t rotate(uint32_t a, uint32_t b) {
    return ((a << b) | (a >> (32 - b)));
}

void *dark_F(struct dark_state *state) {
    int i;
    uint32_t x;
    for (i = 0; i < 8; i++) {
        x = state->r[i];
        state->r[i] = (state->r[i] + state->r[(i + 1) % 8] + state->j) & 0xFFFFFFFF;
        state->r[i] = state->r[i] ^ x;
        state->r[i] = rotate(state->r[i], 2) & 0xFFFFFFFF;
        state->j = (state->j + state->r[i] + state->c) & 0xFFFFFFFF;
        state->c = (state->c + 1) & 0xFFFFFFFF;
    }
}

void dark_keysetup(struct dark_state *state, unsigned char *key, unsigned char *nonce) {
    uint32_t n[4];
    state->r[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    state->r[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    state->r[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    state->r[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    state->r[4] = (key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19];
    state->r[5] = (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    state->r[6] = (key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27];
    state->r[7] = (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];

    n[0] = (nonce[0] << 24) + (nonce[1] << 16) + (nonce[2] << 8) + nonce[3];
    n[1] = (nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7];
    n[2] = (nonce[8] << 24) + (nonce[9] << 16) + (nonce[10] << 8) + nonce[11];
    n[3] = (nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15];

    state->r[4] = state->r[4] ^ n[0];
    state->r[5] = state->r[5] ^ n[1];
    state->r[6] = state->r[6] ^ n[2];
    state->r[7] = state->r[7] ^ n[3];

    state->j = 0;
    state->c = 0;

    for (int i = 0; i < 8; i++) {
        state->j = (state->j + state->r[i]) & 0xFFFFFFFF;
    }
    dark_F(state);
}

void * dark_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
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
    struct dark_state state;
    uint64_t c = 0;
    uint64_t i = 0;
    int l = 4;
    uint32_t output;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    dark_keysetup(&state, keyprime, nonce);
    for (uint64_t b = 0; b < blocks; b++) {
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        for (i = 0; i < (bufsize / 4); i++) {
           dark_F(&state);
           output = (((((((state.r[0] + state.r[6]) ^ state.r[1]) + state.r[5]) ^ state.r[2]) + state.r[4]) ^ state.r[3]) + state.r[7]) & 0xFFFFFFFF;
           k[c] = (output & 0x000000FF);
           k[c+1] = (output & 0x0000FF00) >> 8;
           k[c+2] = (output & 0x00FF0000) >> 16;
           k[c+3] = (output & 0xFF000000) >> 24;
           c += 4;
        }
        for (int i = 0; i < bufsize; i++) {
           buffer[i] = buffer[i] ^ k[i];
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * dark_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
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
    fread(nonce, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);
    struct dark_state state;
    long c = 0;
    uint64_t i = 0;
    int l = 4;
    uint32_t output;
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
        dark_keysetup(&state, keyprime, nonce);
        for (unsigned long long b = 0; b < blocks; b++) {
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            if ((b == (blocks - 1)) && (extra != 0)) {
                bufsize = extra;
            }
            for (i = 0; i < (bufsize / 4); i++) {
                dark_F(&state);
                output = (((((((state.r[0] + state.r[6]) ^ state.r[1]) + state.r[5]) ^ state.r[2]) + state.r[4]) ^ state.r[3]) + state.r[7]) & 0xFFFFFFFF;
                k[c] = (output & 0x000000FF);
                k[c+1] = (output & 0x0000FF00) >> 8;
                k[c+2] = (output & 0x00FF0000) >> 16;
                k[c+3] = (output & 0xFF000000) >> 24;
                c += 4;
            }
            for (int i = 0; i < bufsize; i++) {
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
