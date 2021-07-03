/* KryptoMagick Dark Dragon [2021] */

uint8_t darkdragonS0[256] = {93, 189, 55, 134, 51, 103, 232, 238, 137, 32, 124, 81, 108, 175, 161, 225, 40, 250, 222, 122, 234, 27, 193, 10, 14, 216, 82, 167, 180, 74, 212, 252, 142, 200, 136, 150, 66, 131, 190, 143, 43, 160, 227, 37, 224, 113, 72, 9, 242, 110, 153, 92, 17, 73, 31, 54, 50, 223, 253, 231, 239, 158, 139, 233, 80, 75, 144, 237, 126, 34, 22, 35, 248, 195, 154, 166, 67, 28, 99, 11, 100, 163, 63, 249, 155, 203, 97, 141, 128, 52, 87, 38, 88, 47, 228, 104, 68, 33, 5, 178, 12, 132, 86, 205, 147, 129, 42, 179, 102, 156, 217, 16, 171, 168, 3, 6, 240, 244, 71, 219, 94, 19, 48, 157, 77, 151, 170, 194, 148, 91, 0, 226, 114, 187, 41, 101, 218, 246, 76, 56, 236, 116, 29, 106, 198, 119, 201, 89, 120, 2, 115, 221, 112, 1, 30, 18, 243, 152, 123, 196, 235, 13, 78, 209, 145, 84, 125, 202, 70, 49, 206, 53, 176, 183, 251, 159, 182, 210, 169, 181, 186, 7, 8, 65, 36, 127, 185, 61, 95, 245, 111, 214, 162, 39, 138, 184, 26, 191, 213, 230, 173, 44, 146, 192, 79, 241, 107, 172, 140, 98, 135, 105, 207, 96, 24, 177, 121, 45, 25, 229, 208, 21, 83, 220, 165, 46, 57, 62, 204, 58, 85, 23, 90, 255, 64, 133, 164, 215, 59, 149, 197, 199, 118, 20, 15, 117, 174, 211, 247, 69, 254, 109, 60, 188, 130, 4};
uint8_t darkdragonS1[256] = {153, 79, 48, 69, 228, 117, 106, 251, 205, 220, 105, 57, 46, 3, 37, 217, 158, 233, 62, 213, 89, 119, 229, 144, 218, 27, 75, 192, 127, 231, 178, 80, 42, 24, 53, 134, 133, 250, 189, 160, 175, 43, 103, 124, 247, 237, 100, 68, 244, 31, 34, 70, 163, 121, 215, 108, 238, 180, 162, 5, 4, 239, 226, 17, 181, 199, 198, 172, 236, 171, 116, 51, 90, 173, 19, 148, 165, 63, 115, 76, 182, 161, 129, 10, 234, 56, 211, 50, 126, 131, 83, 174, 146, 13, 95, 157, 186, 67, 253, 176, 188, 212, 21, 248, 159, 91, 193, 2, 40, 169, 29, 101, 98, 155, 168, 135, 136, 15, 120, 203, 113, 225, 52, 71, 33, 49, 1, 130, 104, 85, 170, 99, 202, 38, 156, 73, 210, 25, 28, 14, 84, 6, 243, 222, 147, 246, 11, 184, 122, 223, 197, 245, 20, 58, 195, 114, 26, 77, 65, 109, 230, 227, 41, 208, 123, 32, 44, 36, 235, 23, 221, 145, 64, 141, 167, 138, 102, 191, 209, 214, 241, 137, 128, 18, 194, 206, 151, 110, 204, 164, 224, 249, 166, 30, 242, 254, 107, 94, 183, 61, 86, 93, 7, 54, 252, 47, 8, 125, 82, 74, 35, 92, 201, 16, 190, 154, 207, 112, 140, 149, 179, 87, 55, 142, 60, 139, 12, 111, 59, 97, 177, 118, 66, 22, 45, 240, 187, 152, 132, 78, 219, 72, 185, 0, 96, 39, 81, 200, 255, 150, 196, 143, 88, 216, 9, 232};

uint32_t darkdragonC0[4] = {0xb66329a0, 0xe12dc19c, 0xf906a604, 0xa9856d6b};

struct darkdragon_state {
    uint32_t Z[12];
    uint32_t o;
    uint8_t tmp0[4];
    uint8_t tmp1[4];
};

uint32_t darkdragonG0(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS0[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS0[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS0[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS1[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonG1(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS0[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS0[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS1[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS0[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonG2(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS0[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS1[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS0[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS0[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonG3(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS1[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS0[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS0[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS0[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonH0(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS1[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS1[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS1[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS0[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonH1(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS1[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS1[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS0[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS1[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonH2(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS1[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS0[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS1[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS1[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

uint32_t darkdragonH3(struct darkdragon_state *state, uint32_t w0, uint32_t w1) {
    state->tmp0[0] = (w0 & 0xFF000000) >> 24;
    state->tmp0[1] = (w0 & 0x00FF0000) >> 16;
    state->tmp0[2] = (w0 & 0x0000FF00) >> 8;
    state->tmp0[3] = (w0 & 0x000000FF);
    state->tmp1[0] = (w1 & 0xFF000000) >> 24;
    state->tmp1[1] = (w1 & 0x00FF0000) >> 16;
    state->tmp1[2] = (w1 & 0x0000FF00) >> 8;
    state->tmp1[3] = (w1 & 0x000000FF);
    state->tmp0[0] = state->tmp0[0] ^ darkdragonS0[state->tmp1[0]];
    state->tmp0[1] = state->tmp0[1] ^ darkdragonS1[state->tmp1[1]];
    state->tmp0[2] = state->tmp0[2] ^ darkdragonS1[state->tmp1[2]];
    state->tmp0[3] = state->tmp0[3] ^ darkdragonS1[state->tmp1[3]];
    return ((state->tmp0[0] << 24) + (state->tmp0[1] << 16) + (state->tmp0[2] << 8) + state->tmp0[3]);
}

void darkdragonPreMixing0(struct darkdragon_state *state) {
    state->Z[11] = rotate(state->Z[11], 16);
    state->Z[9] = rotate(state->Z[9], 12);
    state->Z[9] = (state->Z[9] + state->Z[0]) & 0xFFFFFFFF;
    state->Z[11] = state->Z[11] ^ state->Z[2];
    state->Z[5] = (state->Z[5] + state->Z[8]) & 0xFFFFFFFF;
    state->Z[7] = state->Z[7] ^ state->Z[10];
    state->Z[1] = (state->Z[1] + state->Z[6]) & 0xFFFFFFFF;
    state->Z[3] = state->Z[3] ^ state->Z[4];
}

void darkdragonPreMixing1(struct darkdragon_state *state) {
    state->Z[10] = rotate(state->Z[10], 6);
    state->Z[8] = rotate(state->Z[8], 31);
    state->Z[8] = (state->Z[8] + state->Z[7]) & 0xFFFFFFFF;
    state->Z[10] = state->Z[10] ^ state->Z[11];
    state->Z[4] = (state->Z[4] + state->Z[5]) & 0xFFFFFFFF;
    state->Z[6] = state->Z[6] ^ state->Z[8];
    state->Z[2] = (state->Z[2] + state->Z[1]) & 0xFFFFFFFF;
    state->Z[0] = state->Z[0] ^ state->Z[3];
}

void darkdragonSBoxLayer0(struct darkdragon_state *state) {
    state->Z[3] = darkdragonG0(state, state->Z[3], state->Z[0]);
    state->Z[5] = darkdragonG1(state, state->Z[5], state->Z[2]);
    state->Z[7] = darkdragonG2(state, state->Z[7], state->Z[4]);
    state->Z[1] = darkdragonG3(state, state->Z[1], state->Z[6]);
}

void darkdragonSBoxLayer1(struct darkdragon_state *state) {
    state->Z[2] = darkdragonH0(state, state->Z[2], state->Z[1]);
    state->Z[4] = darkdragonH1(state, state->Z[4], state->Z[3]);
    state->Z[0] = darkdragonH2(state, state->Z[0], state->Z[5]);
    state->Z[6] = darkdragonH3(state, state->Z[6], state->Z[7]);
}

void darkdragonPostMixing0(struct darkdragon_state *state) {
    state->Z[3] = (state->Z[3] + state->Z[0]) & 0xFFFFFFFF;
    state->Z[1] = state->Z[1] ^ state->Z[2];
    state->Z[7] = (state->Z[7] + state->Z[6]) & 0xFFFFFFFF;
    state->Z[5] = state->Z[5] ^ state->Z[4];
}

void darkdragonPostMixing1(struct darkdragon_state *state) {
    state->Z[0] = (state->Z[0] + state->Z[7]) & 0xFFFFFFFF;
    state->Z[2] = state->Z[2] ^ state->Z[5];
    state->Z[4] = (state->Z[4] + state->Z[1]) & 0xFFFFFFFF;
    state->Z[6] = state->Z[6] ^ state->Z[3];
}

void darkdragonPostMixing2(struct darkdragon_state *state) {
    state->Z[8] = (state->Z[8] + state->Z[11]) & 0xFFFFFFFF;
    state->Z[10] = state->Z[10] ^ state->Z[9];
}

void darkdragonPostMixing3(struct darkdragon_state *state) {
    state->Z[11] = (state->Z[11] + state->Z[10]) & 0xFFFFFFFF;
    state->Z[9] = state->Z[9] ^ state->Z[8];
}

void darkdragonOutput(struct darkdragon_state *state) {
    state->o = 0;
    state->o ^= state->Z[0];
    state->o ^= state->Z[1];
    state->o ^= state->Z[2];
    state->o ^= state->Z[3];
    state->o ^= state->Z[4];
    state->o ^= state->Z[5];
    state->o ^= state->Z[6];
    state->o ^= state->Z[7];
}

void darkdragonUpdate(struct darkdragon_state *state) {
    darkdragonPreMixing0(state);
    darkdragonPreMixing1(state);
    darkdragonSBoxLayer0(state);
    darkdragonSBoxLayer1(state);
    darkdragonPostMixing0(state);
    darkdragonPostMixing1(state);
    darkdragonPostMixing2(state);
    darkdragonPostMixing3(state);
    darkdragonOutput(state);
}

void darkdragon_keysetup(struct darkdragon_state *state, unsigned char *key, unsigned char *nonce) {
    memset(state->Z, 0, 12*(sizeof(uint32_t)));
    memset(state->tmp0, 0, 4*(sizeof(uint32_t)));
    memset(state->tmp1, 0, 4*(sizeof(uint32_t)));
    state->Z[11] = darkdragonC0[0];
    state->Z[10] = darkdragonC0[1];
    state->Z[9] = darkdragonC0[2];
    state->Z[8] = darkdragonC0[3];

    state->Z[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    state->Z[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    state->Z[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    state->Z[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    state->Z[4] = (key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19];
    state->Z[5] = (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    state->Z[6] = (key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27];
    state->Z[7] = (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];

    state->Z[8] ^= ((nonce[0] << 24) + (nonce[1] << 16) + (nonce[2] << 8) + nonce[3]);
    state->Z[9] ^= ((nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7]);
    state->Z[10] ^= ((nonce[8] << 24) + (nonce[9] << 16) + (nonce[10] << 8) + nonce[11]);
    state->Z[11] ^= ((nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15]);

    for (int i = 0; i < 2; i++) {
        darkdragonUpdate(state);
    }
}

void * darkdragon_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);
    load_pkfile(keyfile1, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);

    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    unsigned char S[crypto_sign_BYTES];
    amagus_random(K, key_length);
    unsigned char *passwctxt[crypto_box_SEALBYTES + key_length];
    crypto_box_seal(passwctxt, K, key_length, pkB);
    crypto_sign_detached(S, NULL, passwctxt, crypto_box_SEALBYTES + key_length, Ssk);
    manja_kdf(K, key_length, key, key_length, kdf_salt, salt_len, kdf_iterations);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(S, 1, crypto_sign_BYTES, outfile);
    fwrite(passwctxt, 1, crypto_box_SEALBYTES + key_length, outfile);
    fwrite(nonce, 1, nonce_length, outfile);
    struct darkdragon_state state;
    uint64_t c = 0;
    uint64_t i = 0;
    int l = 4;
    int k[bufsize];
    memset(k, 0, bufsize);
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    darkdragon_keysetup(&state, key, nonce);
    for (uint64_t b = 0; b < blocks; b++) {
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        for (i = 0; i < (bufsize / 4); i++) {
           darkdragonUpdate(&state);
           k[c] = (state.o & 0xFF000000) >> 24;
           k[c+1] = (state.o & 0x00FFFF00) >> 16;
           k[c+2] = (state.o & 0x0000FF00) >> 8;
           k[c+3] = (state.o & 0x000000FF);
           c += 4;
        }
        for (int i = 0; i < bufsize; i++) {
           buffer[i] = buffer[i] ^ k[i];
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * darkdragon_decrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);
    load_pkfile(keyfile2, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);

    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char nonce[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *passtmp[crypto_box_SEALBYTES + key_length];
    unsigned char S[crypto_sign_BYTES];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - crypto_box_SEALBYTES - crypto_sign_BYTES;

    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(S, 1, crypto_sign_BYTES, infile);
    fread(passtmp, 1, crypto_box_SEALBYTES + key_length, infile);
    fread(nonce, 1, nonce_length, infile);
    if (crypto_sign_verify_detached(S, passtmp, crypto_box_SEALBYTES + key_length, SpkB) == 0) {
        if (crypto_box_seal_open(keyprime, passtmp, crypto_box_SEALBYTES + key_length, pk, sk) != 0) {
            printf("Error: Public key decryption failed.\n");
            exit(-1);
        }
    }
    else {
         printf("Error: Signature verification failed. Message is not authentic.\n");
         exit(-1);
    }
    manja_kdf(keyprime, key_length, key, key_length, kdf_salt, salt_len, kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    struct darkdragon_state state;
    long c = 0;
    uint64_t i = 0;
    int l = 4;
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
        fseek(infile, (mac_length + nonce_length + key_length + crypto_box_SEALBYTES + crypto_sign_BYTES), SEEK_SET);
        darkdragon_keysetup(&state, key, nonce);
        for (unsigned long long b = 0; b < blocks; b++) {
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            if ((b == (blocks - 1)) && (extra != 0)) {
                bufsize = extra;
            }
            for (i = 0; i < (bufsize / 4); i++) {
                darkdragonUpdate(&state);
                k[c] = (state.o & 0xFF000000) >> 24;
                k[c+1] = (state.o & 0x00FF0000) >> 16;
                k[c+2] = (state.o & 0x0000FF00) >> 8;
                k[c+3] = (state.o & 0x000000FF);
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
