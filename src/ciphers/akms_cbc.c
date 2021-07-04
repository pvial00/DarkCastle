/* KryptoMagick AKMS Kuzynki (256) Cipher [2021] */

int akmsSR[4] = {0, 1, 2, 3};

uint8_t akmsS0[256] = {117, 12, 48, 75, 111, 232, 123, 193, 125, 231, 121, 91, 122, 14, 11, 92, 173, 80, 54, 208, 31, 160, 0, 150, 159, 58, 76, 50, 105, 236, 114, 156, 33, 104, 5, 222, 53, 42, 99, 81, 87, 201, 132, 71, 139, 25, 13, 176, 59, 49, 148, 190, 182, 130, 29, 65, 84, 16, 223, 89, 118, 106, 157, 209, 110, 129, 175, 41, 171, 181, 131, 113, 141, 170, 4, 144, 38, 206, 179, 248, 128, 167, 6, 228, 188, 90, 96, 102, 73, 51, 15, 57, 154, 213, 230, 74, 169, 93, 36, 78, 2, 149, 189, 7, 155, 239, 227, 77, 82, 136, 9, 178, 112, 79, 17, 243, 37, 23, 172, 22, 28, 244, 229, 225, 238, 192, 191, 34, 134, 207, 161, 198, 164, 196, 220, 86, 221, 18, 3, 142, 35, 233, 215, 94, 137, 250, 19, 62, 98, 46, 68, 100, 85, 241, 27, 202, 138, 10, 107, 56, 205, 61, 21, 211, 101, 168, 64, 200, 30, 67, 165, 174, 195, 251, 163, 103, 45, 226, 135, 8, 83, 133, 185, 180, 219, 246, 115, 24, 210, 72, 187, 253, 242, 124, 204, 88, 255, 166, 109, 197, 151, 70, 63, 44, 60, 235, 247, 186, 143, 126, 32, 162, 194, 66, 95, 146, 214, 147, 97, 40, 152, 177, 216, 140, 153, 224, 26, 237, 127, 43, 1, 183, 234, 249, 158, 108, 217, 116, 245, 52, 212, 199, 119, 55, 20, 39, 240, 47, 252, 69, 203, 218, 184, 254, 145, 120};
uint8_t akmsSI0[256] = {22, 230, 100, 138, 74, 34, 82, 103, 179, 110, 157, 14, 1, 46, 13, 90, 57, 114, 137, 146, 244, 162, 119, 117, 187, 45, 226, 154, 120, 54, 168, 20, 210, 32, 127, 140, 98, 116, 76, 245, 219, 67, 37, 229, 203, 176, 149, 247, 2, 49, 27, 89, 239, 36, 18, 243, 159, 91, 25, 48, 204, 161, 147, 202, 166, 55, 213, 169, 150, 249, 201, 43, 189, 88, 95, 3, 26, 107, 99, 113, 17, 39, 108, 180, 56, 152, 135, 40, 195, 59, 85, 11, 15, 97, 143, 214, 86, 218, 148, 38, 151, 164, 87, 175, 33, 28, 61, 158, 235, 198, 64, 4, 112, 71, 30, 186, 237, 0, 60, 242, 255, 10, 12, 6, 193, 8, 209, 228, 80, 65, 53, 70, 42, 181, 128, 178, 109, 144, 156, 44, 223, 72, 139, 208, 75, 254, 215, 217, 50, 101, 23, 200, 220, 224, 92, 104, 31, 62, 234, 24, 21, 130, 211, 174, 132, 170, 197, 81, 165, 96, 73, 68, 118, 16, 171, 66, 47, 221, 111, 78, 183, 69, 52, 231, 252, 182, 207, 190, 84, 102, 51, 126, 125, 7, 212, 172, 133, 199, 131, 241, 167, 41, 155, 250, 194, 160, 77, 129, 19, 63, 188, 163, 240, 93, 216, 142, 222, 236, 251, 184, 134, 136, 35, 58, 225, 123, 177, 106, 83, 122, 94, 9, 5, 141, 232, 205, 29, 227, 124, 105, 246, 153, 192, 115, 121, 238, 185, 206, 79, 233, 145, 173, 248, 191, 253, 196};
uint8_t akmsA0[256] = {75, 173, 9, 29, 71, 117, 69, 83, 31, 97, 55, 95, 161, 81, 129, 233, 105, 239, 83, 65, 81, 63, 103, 211, 1, 29, 251, 171, 49, 191, 27, 57, 15, 203, 181, 213, 243, 61, 17, 73, 147, 237, 203, 201, 253, 159, 169, 35, 61, 39, 133, 107, 165, 77, 187, 13, 155, 63, 3, 223, 119, 185, 147, 89, 149, 19, 153, 49, 51, 53, 21, 91, 217, 27, 225, 169, 43, 45, 175, 171, 5, 121, 155, 117, 101, 5, 45, 75, 251, 41, 207, 233, 219, 127, 221, 59, 229, 137, 17, 235, 211, 231, 127, 99, 73, 21, 11, 195, 77, 199, 59, 167, 109, 189, 183, 97, 51, 153, 139, 55, 247, 245, 67, 151, 53, 107, 41, 213, 237, 65, 85, 15, 11, 13, 47, 115, 215, 205, 131, 245, 227, 199, 183, 123, 135, 225, 113, 207, 185, 173, 43, 7, 101, 69, 181, 123, 125, 209, 129, 9, 119, 241, 157, 79, 141, 145, 255, 33, 99, 231, 179, 161, 193, 103, 141, 93, 223, 229, 19, 151, 221, 79, 25, 235, 87, 121, 111, 105, 189, 137, 159, 91, 115, 67, 111, 217, 143, 37, 163, 177, 125, 253, 87, 143, 37, 243, 139, 247, 23, 1, 113, 249, 175, 93, 255, 85, 209, 191, 201, 31, 177, 179, 23, 71, 219, 145, 249, 149, 133, 157, 57, 7, 25, 3, 131, 187, 205, 35, 109, 241, 39, 89, 239, 215, 47, 165, 167, 95, 193, 197, 197, 163, 195, 135, 33, 227};
uint8_t akmsAI0[256] = {99, 37, 57, 53, 119, 221, 141, 219, 223, 161, 135, 159, 97, 177, 129, 89, 217, 15, 219, 193, 177, 191, 87, 91, 1, 53, 51, 3, 209, 63, 19, 9, 239, 227, 157, 125, 59, 21, 241, 249, 155, 229, 227, 121, 85, 95, 153, 139, 21, 151, 77, 67, 45, 133, 115, 197, 147, 191, 171, 31, 71, 137, 155, 233, 189, 27, 169, 209, 251, 29, 61, 211, 105, 19, 33, 153, 131, 165, 79, 3, 205, 201, 147, 221, 109, 205, 165, 99, 51, 25, 47, 89, 83, 127, 117, 243, 237, 185, 241, 195, 91, 215, 127, 75, 249, 61, 163, 235, 133, 247, 243, 23, 101, 149, 7, 161, 251, 169, 35, 135, 199, 93, 107, 39, 29, 67, 25, 125, 229, 193, 253, 239, 163, 197, 207, 187, 231, 5, 43, 93, 203, 247, 7, 179, 55, 33, 145, 47, 137, 37, 131, 183, 109, 141, 157, 179, 213, 49, 129, 57, 71, 17, 181, 175, 69, 113, 255, 225, 75, 215, 123, 97, 65, 87, 69, 245, 31, 237, 27, 39, 117, 175, 41, 195, 103, 201, 143, 217, 149, 185, 95, 211, 187, 107, 143, 105, 111, 173, 11, 81, 213, 85, 103, 111, 173, 59, 35, 199, 167, 1, 145, 73, 79, 245, 255, 253, 49, 63, 121, 223, 81, 123, 167, 119, 83, 113, 73, 189, 77, 181, 9, 183, 41, 171, 43, 115, 5, 139, 101, 17, 151, 233, 15, 231, 207, 45, 23, 159, 65, 13, 13, 11, 235, 55, 225, 203};

uint32_t akmsC0[4] = {0xd419dd28, 0xe2be508d, 0xc7d77bcd, 0xf92730ad};

struct akmsState {
    uint32_t R[14][4];
    uint8_t M[4][4];
    uint8_t last[4][4];
    uint8_t next[4][4];
    int rounds;
    int blocklen;
};

struct akmsksaState {
    uint32_t r[16];
    uint32_t o;
};

uint64_t akms_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t akms_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *akms_F(struct akmsksaState *state) {
    int r;
    uint32_t *tmp[16];
    memcpy(tmp, state->r, 16*(sizeof(uint32_t)));
    for (r = 0; r < 16; r++) {
        state->r[0] += state->r[4];
        state->r[1] = akms_rotl((state->r[1] ^ state->r[10]), 22);
        state->r[2] += state->r[12];
        state->r[3] = akms_rotl((state->r[3] ^ state->r[8]), 25);
        state->r[4] += state->r[5];
        state->r[5] = akms_rotl((state->r[5] ^ state->r[2]), 12);
        state->r[6] += state->r[7];
        state->r[7] = akms_rotl((state->r[7] ^ state->r[0]), 29);
        state->r[8] += state->r[9];
        state->r[9] = akms_rotl((state->r[9] ^ state->r[14]), 2);
        state->r[10] += state->r[11];
        state->r[11] = akms_rotl((state->r[11] ^ state->r[1]), 7);
        state->r[12] += state->r[13];
        state->r[13] = akms_rotl((state->r[13] ^ state->r[15]), 13);
        state->r[14] += state->r[3];
        state->r[15] = akms_rotl((state->r[15] ^ state->r[6]), 9);
    }
    state->o = 0;
    for (r = 0; r < 16; r++) {
        state->r[r] += tmp[r];
        state->o ^= state->r[r];
    }
}

void akmsgenRoundKeys(struct akmsState * state, unsigned char * key, int keylen) {
    struct akmsksaState kstate;
    int c = 0;
    int i;
    int q;
    memset(&kstate.r, 0, 16*sizeof(uint32_t));
    memset(&kstate.o, 0, sizeof(uint32_t));
    kstate.r[12] = akmsC0[0];
    kstate.r[13] = akmsC0[1];
    kstate.r[14] = akmsC0[2];
    kstate.r[15] = akmsC0[3];
    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] ^= ((uint64_t)key[c] << 24) + ((uint64_t)key[c+1] << 16) + ((uint64_t)key[c+2] << 8) + (uint64_t)key[c+3];
        c += 4;
    }
    for (i = 0; i < state->rounds; i++) {
        for (q = 0; q < 4; q++) {
            akms_F(&kstate);
            state->R[i][q] = 0;
	    state->R[i][q] = kstate.o;
        }
    }
}

void loadInIV(struct akmsState *state, unsigned char *iv) {
    int c = 0;
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            state->last[q][i] = (uint8_t)iv[c];
            c += 1;
        }
    }
}

void loadInMatrix(struct akmsState *state, uint8_t *block) {
    int c = 0;
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            state->M[q][i] = block[c];
            c += 1;
        }
    }
}

void loadOutMatrix(struct akmsState *state, uint8_t *block) {
    int c = 0;
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            block[c] = state->M[q][i]; 
            c += 1;
        }
    }
}

void SubBytes(struct akmsState *state) {
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            state->M[q][i] = akmsS0[((akmsS0[state->M[q][i]] * akmsA0[state->M[q][(i - 1) & 0x03]]) ^ state->M[q][(i + 1) & 0x03]) & 0xFF];
        }
    }
}

void InvSubBytes(struct akmsState *state) {
    for (int q = 3; q != -1; q--) {
        for (int i = 3; i != -1; i--) {
            state->M[q][i] = akmsSI0[((akmsSI0[state->M[q][i]] ^ state->M[q][(i + 1) & 0x03]) * akmsAI0[state->M[q][(i - 1) & 0x03]]) & 0xFF];
        }
    }
}

void shiftRow(uint8_t *block, int blocklen, int shift) {
    uint8_t tmp; 
    for (int x = 0; x < shift; x++) {
        for (int y = blocklen - 1; y != 0; y--) {
            tmp = block[y];
            block[y] = block[(y + 1) & 0x03];
            block[(y + 1) & 0x03] = tmp;
        }
    }
}

void InvShiftRow(uint8_t *block, int blocklen, int shift) {
    uint8_t tmp;
    for (int x = 0; x < shift; x++) {
        for (int y = 0; y < blocklen - 1; y++) {
            tmp = block[y];
            block[y] = block[(y + 1) & 0x03];
            block[(y + 1) & 0x03] = tmp;
        }
    }
}

void ShiftRows(struct akmsState *state) {
    for (int x = 1; x < 4; x++) {
        shiftRow(state->M[x], 4, akmsSR[x]);
    }
}

void InvShiftRows(struct akmsState *state) {
    for (int x = 3; x != 0; x--) {
        InvShiftRow(state->M[x], 4, akmsSR[x]);
    }
}

void MixColumns(struct akmsState *state) {
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            state->M[q][i] = (((akmsA0[state->M[q][(i - 1) & 0x03]] * state->M[q][i]) + state->M[(q + 1) & 0x03][i]) & 0xFF) ^ state->M[q][(i + 1) & 0x03];
        }
    }
}

void InvMixColumns(struct akmsState *state) {
    for (int q = 3; q != -1; q--) {
        for (int i = 3; i != -1; i--) {
            state->M[q][i] = (((state->M[q][i] ^ state->M[q][(i + 1) & 0x03]) - state->M[(q + 1) & 0x03][i]) * akmsAI0[state->M[q][(i - 1) & 0x03]]) & 0xFF;
        }
    }
}

void AddRoundKey(struct akmsState *state, int r) {
    int c = 24;
    int x = 0;
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            state->M[q][i] ^= (uint8_t)state->R[r][x] << c;
            c -= 8;
        }
        x += 1;
    }
}

uint64_t akmsBlockEnc(struct akmsState * state) {
    for (int r = 0; r < state->rounds; r++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, r);
    }
}

uint64_t akmsBlockDec(struct akmsState * state) {
    for (int r = state->rounds - 1; r != -1; r--) {
        AddRoundKey(state, r);
        InvMixColumns(state);
        InvShiftRows(state);
        InvSubBytes(state);
    }
}

void akmsCBC(struct akmsState *state) {
    int c = 0;
    for (int q = 0; q < 4; q++) {
        for (int i = 0; i < 4; i++) {
            state->M[q][i] ^= state->last[q][i];
        }
    }
}

void akmsCBCSaveEnc(struct akmsState *state) {
    memcpy(state->last, state->M, 4*4*(sizeof(uint8_t)));
}

void akmsCBCSaveDec(struct akmsState *state) {
    memcpy(state->next, state->M, 4*4*(sizeof(uint8_t)));
}

void akmsCBCSaveDec2(struct akmsState *state) {
    memcpy(state->last, state->next, 4*4*(sizeof(uint8_t)));
}

void * akms_cbc_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
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
    unsigned char S[crypto_sign_BYTES];
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);
    load_pkfile(keyfile1, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);
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
    fwrite(iv, 1, nonce_length, outfile);

    struct akmsState state;
    state.blocklen = 16;
    state.rounds = 14;
    uint8_t block[16] = {0};
    int blocksize = 16;
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
    loadInIV(&state, iv);
    akmsgenRoundKeys(&state, key, key_length);
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
            for (int x = 0; x < state.blocklen; x++) {
                block[x] = (uint8_t)buffer[c+x];
            }
            loadInMatrix(&state, block);
            akmsCBC(&state);
            akmsBlockEnc(&state);
            akmsCBCSaveEnc(&state);
            loadOutMatrix(&state, block);
            for (int x = 0; x < state.blocklen; x++) {
                buffer[c+x] = (unsigned char)block[x];
            }
            c += state.blocklen;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * akms_cbc_decrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
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
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *passtmp[(crypto_box_SEALBYTES + key_length)];
    unsigned char S[crypto_sign_BYTES];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    int extrabytes = 16 - (datalen % 16);
    fseek(infile, 0, SEEK_SET);

    fread(&mac, 1, mac_length, infile);
    fread(S, 1, crypto_sign_BYTES, infile);
    fread(passtmp, 1, crypto_box_SEALBYTES + key_length, infile);
    fread(iv, 1, nonce_length, infile);
    datalen = datalen - key_length - mac_length - nonce_length - crypto_box_SEALBYTES - crypto_sign_BYTES;
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

    struct akmsState state;
    state.blocklen = 16;
    state.rounds = 14;
    int count = 0;
    uint8_t block[16] = {0};
    int blocksize = 16;
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
        fseek(infile, (mac_length + nonce_length + key_length +  crypto_box_SEALBYTES + crypto_sign_BYTES), SEEK_SET);
        loadInIV(&state, iv);
        akmsgenRoundKeys(&state, key, key_length);
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
                for (int x = 0; x < state.blocklen; x++) {
                    block[x] = (uint8_t)buffer[c+x];
                }
                loadInMatrix(&state, block);
                akmsCBCSaveDec(&state);
                akmsBlockDec(&state);
                akmsCBC(&state);
                akmsCBCSaveDec2(&state);
                loadOutMatrix(&state, block);
                for (int x = 0; x < state.blocklen; x++) {
                    buffer[c+x] = (unsigned char)block[x];
                }
                c += state.blocklen;
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
