/* KryptoMagick Albion Cipher [2021] */

uint8_t albionS0[256] = {59, 154, 94, 100, 170, 118, 163, 19, 178, 102, 126, 245, 157, 166, 66, 121, 28, 231, 189, 46, 221, 134, 179, 55, 142, 82, 105, 177, 195, 18, 41, 135, 244, 79, 113, 182, 193, 30, 42, 78, 239, 147, 14, 131, 48, 226, 207, 119, 21, 136, 49, 222, 129, 192, 201, 37, 199, 1, 52, 205, 151, 249, 50, 133, 43, 181, 236, 92, 216, 56, 36, 174, 64, 39, 200, 212, 87, 130, 143, 29, 145, 107, 5, 140, 35, 25, 32, 89, 74, 227, 223, 53, 167, 153, 3, 232, 159, 24, 106, 96, 104, 194, 241, 160, 206, 38, 4, 110, 112, 235, 71, 202, 76, 209, 210, 141, 73, 155, 233, 246, 132, 81, 173, 190, 77, 88, 125, 183, 176, 6, 97, 98, 234, 225, 214, 26, 217, 203, 164, 252, 156, 191, 197, 90, 83, 68, 215, 99, 86, 40, 15, 47, 17, 120, 161, 172, 10, 185, 93, 103, 7, 123, 175, 13, 117, 33, 12, 230, 180, 218, 31, 240, 158, 101, 114, 255, 122, 116, 150, 224, 138, 229, 211, 248, 186, 168, 109, 108, 146, 213, 237, 51, 16, 23, 65, 144, 95, 70, 220, 162, 228, 45, 44, 54, 152, 63, 128, 149, 254, 58, 22, 204, 253, 139, 34, 148, 60, 111, 85, 165, 115, 67, 242, 27, 251, 250, 8, 198, 84, 91, 69, 243, 72, 75, 169, 219, 0, 124, 62, 11, 57, 196, 247, 2, 137, 187, 184, 9, 238, 80, 20, 208, 61, 171, 188, 127};
uint8_t albionSI0[256] = {236, 57, 243, 94, 106, 82, 129, 160, 226, 247, 156, 239, 166, 163, 42, 150, 192, 152, 29, 7, 250, 48, 210, 193, 97, 85, 135, 223, 16, 79, 37, 170, 86, 165, 214, 84, 70, 55, 105, 73, 149, 30, 38, 64, 202, 201, 19, 151, 44, 50, 62, 191, 58, 91, 203, 23, 69, 240, 209, 0, 216, 252, 238, 205, 72, 194, 14, 221, 145, 230, 197, 110, 232, 116, 88, 233, 112, 124, 39, 33, 249, 121, 25, 144, 228, 218, 148, 76, 125, 87, 143, 229, 67, 158, 2, 196, 99, 130, 131, 147, 3, 173, 9, 159, 100, 26, 98, 81, 187, 186, 107, 217, 108, 34, 174, 220, 177, 164, 5, 47, 153, 15, 176, 161, 237, 126, 10, 255, 206, 52, 77, 43, 120, 63, 21, 31, 49, 244, 180, 213, 83, 115, 24, 78, 195, 80, 188, 41, 215, 207, 178, 60, 204, 93, 1, 117, 140, 12, 172, 96, 103, 154, 199, 6, 138, 219, 13, 92, 185, 234, 4, 253, 155, 122, 71, 162, 128, 27, 8, 22, 168, 65, 35, 127, 246, 157, 184, 245, 254, 18, 123, 141, 53, 36, 101, 28, 241, 142, 227, 56, 74, 54, 111, 137, 211, 59, 104, 46, 251, 113, 114, 182, 75, 189, 134, 146, 68, 136, 169, 235, 198, 20, 51, 90, 179, 133, 45, 89, 200, 181, 167, 17, 95, 118, 132, 109, 66, 190, 248, 40, 171, 102, 222, 231, 32, 11, 119, 242, 183, 61, 225, 224, 139, 212, 208, 175};

uint32_t albionC0[8] = {0xd419dd28, 0xe2be508d, 0xc7d77bcd, 0xf92730ad, 0xba943336, 0xd9700b94, 0xe89147b7, 0xd835c940};

struct albionState {
    uint32_t K[14][8];
    uint32_t B[8];
    uint32_t PRK[8];
    uint32_t POK[8];
    uint32_t last[8];
    uint32_t next[8];
    int rounds;
    int blocklen;
};

struct albionksaState {
    uint32_t r[16];
    uint32_t o;
};

uint32_t albion_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t albion_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void *albion_F(struct albionksaState *state) {
    int r;
    uint32_t tmp[16];
    memcpy(tmp, state->r, 16*(sizeof(uint32_t)));
    for (r = 0; r < 16; r++) {
        state->r[0] += state->r[4];
        state->r[1] = albion_rotl((state->r[1] ^ state->r[10]), 22);
        state->r[2] += state->r[12];
        state->r[3] = albion_rotl((state->r[3] ^ state->r[8]), 25);
        state->r[4] += state->r[5];
        state->r[5] = albion_rotl((state->r[5] ^ state->r[2]), 12);
        state->r[6] += state->r[7];
        state->r[7] = albion_rotl((state->r[7] ^ state->r[0]), 29);
        state->r[8] += state->r[9];
        state->r[9] = albion_rotl((state->r[9] ^ state->r[14]), 2);
        state->r[10] += state->r[11];
        state->r[11] = albion_rotl((state->r[11] ^ state->r[1]), 7);
        state->r[12] += state->r[13];
        state->r[13] = albion_rotl((state->r[13] ^ state->r[15]), 13);
        state->r[14] += state->r[3];
        state->r[15] = albion_rotl((state->r[15] ^ state->r[6]), 9);
    }
    state->o = 0;
    for (r = 0; r < 16; r++) {
        state->r[r] += tmp[r];
        state->o ^= state->r[r];
    }
}

void albiongenRoundKeys(struct albionState * state, unsigned char * key, int keylen) {
    struct albionksaState kstate;
    int c = 0;
    int i;
    int q;
    memset(&kstate.r, 0, 16*sizeof(uint32_t));
    memset(&kstate.o, 0, sizeof(uint32_t));
    kstate.r[8] = albionC0[0];
    kstate.r[9] = albionC0[1];
    kstate.r[10] = albionC0[2];
    kstate.r[11] = albionC0[3];
    kstate.r[12] = albionC0[4];
    kstate.r[13] = albionC0[5];
    kstate.r[14] = albionC0[6];
    kstate.r[15] = albionC0[7];
    for (i = 0; i < (keylen / 4); i++) {
        kstate.r[i] ^= (key[c] << 24) + (key[c+1] << 16) + (key[c+2] << 8) + key[c+3];
        c += 4;
    }
    for (i = 0; i < state->rounds; i++) {
        for (q = 0; q < 8; q++) {
            albion_F(&kstate);
            state->K[i][q] = 0;
	    state->K[i][q] = kstate.o;
        }
    }
    for (q = 0; q < 8; q++) {
        albion_F(&kstate);
        state->POK[q] = 0;
        state->POK[q] = kstate.o;
    }
    for (q = 0; q < 8; q++) {
        albion_F(&kstate);
        state->PRK[q] = 0;
        state->PRK[q] = kstate.o;
    }
}

void loadInIVALBI(struct albionState *state, unsigned char *iv) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
       state->last[q] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
       c += 4;
    }
}

void loadInBlock(struct albionState *state, uint8_t *block) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
        state->B[q] = (block[c] << 24) + (block[c+1] << 16) + (block[c+2] << 8) + block[c+3];
        c += 4;
    }
}

void loadOutBlock(struct albionState *state, uint8_t *block) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
        block[c] = state->B[q] >> 24; 
        block[c+1] = state->B[q] >> 16; 
        block[c+2] = state->B[q] >> 8; 
        block[c+3] = state->B[q]; 
        c += 4;
    }
}

void IPALBI(struct albionState *state) {
    albion_rotl(state->B[0], 31);
    albion_rotl(state->B[1], 29);
    albion_rotl(state->B[2], 24);
    albion_rotl(state->B[3], 19);
    albion_rotl(state->B[4], 16);
    albion_rotl(state->B[5], 12);
    albion_rotl(state->B[6], 8);
    albion_rotl(state->B[7], 2);
}

void InvIPALBI(struct albionState *state) {
    albion_rotr(state->B[0], 31);
    albion_rotr(state->B[1], 29);
    albion_rotr(state->B[2], 24);
    albion_rotr(state->B[3], 19);
    albion_rotr(state->B[4], 16);
    albion_rotr(state->B[5], 12);
    albion_rotr(state->B[6], 8);
    albion_rotr(state->B[7], 2);
}

void IMALBI(struct albionState *state) {
    state->B[0] += state->B[4];
    state->B[1] += state->B[5];
    state->B[2] += state->B[6];
    state->B[3] += state->B[7];
    state->B[4] += state->B[0];
    state->B[5] += state->B[1];
    state->B[6] += state->B[2];
    state->B[7] += state->B[3];
}

void InvIMALBI(struct albionState *state) {
    state->B[7] -= state->B[3];
    state->B[6] -= state->B[2];
    state->B[5] -= state->B[1];
    state->B[4] -= state->B[0];
    state->B[3] -= state->B[7];
    state->B[2] -= state->B[6];
    state->B[1] -= state->B[5];
    state->B[0] -= state->B[4];
}

void Sub8ALBI(struct albionState *state) {
    for (int q = 0; q < 8; q++) {
       state->B[q] = (albionS0[(state->B[q] >> 24) & 0xFF] << 24) + (albionS0[(state->B[q] >> 16) & 0xFF] << 16) + (albionS0[(state->B[q] >> 8) & 0xFF] << 8) + albionS0[state->B[q] & 0xFF];
    }
}

void InvSub8ALBI(struct albionState *state) {
    for (int q = 7; q != -1; q--) {
        state->B[q] = (albionSI0[(state->B[q] >> 24) & 0xFF] << 24) + (albionSI0[(state->B[q] >> 16) & 0xFF] << 16) + (albionSI0[(state->B[q] >> 8) & 0xFF] << 8) + albionSI0[state->B[q] & 0xFF];
    }
}

void Rotate8ALBI(struct albionState *state) {
    albion_rotl(state->B[0], 2);
    albion_rotl(state->B[1], 8);
    albion_rotl(state->B[2], 12);
    albion_rotl(state->B[3], 16);
    albion_rotl(state->B[4], 19);
    albion_rotl(state->B[5], 24);
    albion_rotl(state->B[6], 29);
    albion_rotl(state->B[7], 31);
}

void InvRotate8ALBI(struct albionState *state) {
    albion_rotr(state->B[0], 2);
    albion_rotr(state->B[1], 8);
    albion_rotr(state->B[2], 12);
    albion_rotr(state->B[3], 16);
    albion_rotr(state->B[4], 19);
    albion_rotr(state->B[5], 24);
    albion_rotr(state->B[6], 29);
    albion_rotr(state->B[7], 31);
}

void Mix8ALBI(struct albionState *state) {
    state->B[0] += state->B[4];
    state->B[4] += state->B[1];
    state->B[1] += state->B[5];
    state->B[5] += state->B[2];
    state->B[2] += state->B[6];
    state->B[6] += state->B[3];
    state->B[3] += state->B[7];
    state->B[7] += state->B[0];
}

void InvMix8ALBI(struct albionState *state) {
    state->B[7] -= state->B[0];
    state->B[3] -= state->B[7];
    state->B[6] -= state->B[3];
    state->B[2] -= state->B[6];
    state->B[5] -= state->B[2];
    state->B[1] -= state->B[5];
    state->B[4] -= state->B[1];
    state->B[0] -= state->B[4];
}

void AddRoundKeyALBI(struct albionState *state, int r) {
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->K[r][q];
    }
}

void AddPRKALBI(struct albionState *state) {
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->PRK[q];
    }
}

void AddPOKALBI(struct albionState *state) {
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->POK[q];
    }
}

uint64_t albionBlockEnc(struct albionState * state) {
    AddPRKALBI(state);
    IPALBI(state);
    IMALBI(state);
    for (int r = 0; r < state->rounds; r++) {
        Sub8ALBI(state);
        Rotate8ALBI(state);
        Mix8ALBI(state);
        AddRoundKeyALBI(state, r);
    }
    AddPOKALBI(state);
}

uint64_t albionBlockDec(struct albionState * state) {
    AddPOKALBI(state);
    for (int r = state->rounds - 1; r != -1; r--) {
        AddRoundKeyALBI(state, r);
        InvMix8ALBI(state);
        InvRotate8ALBI(state);
        InvSub8ALBI(state);
    }
    InvIMALBI(state);
    InvIPALBI(state);
    AddPRKALBI(state);
}

void albionCBC(struct albionState *state) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->last[q];
    }
}

void albionCBCSaveEnc(struct albionState *state) {
    memcpy(state->last, state->B, 8*(sizeof(uint32_t)));
}

void albionCBCSaveDec(struct albionState *state) {
    memcpy(state->next, state->B, 8*(sizeof(uint32_t)));
}

void albionCBCSaveDec2(struct albionState *state) {
    memcpy(state->last, state->next, 8*(sizeof(uint32_t)));
}

void * albion_cbc_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int bufsize, unsigned char * passphrase) {
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

    struct albionState state;
    state.blocklen = 32;
    state.rounds = 14;
    uint8_t block[32] = {0};
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
    loadInIVALBI(&state, iv);
    albiongenRoundKeys(&state, key, key_length);
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
            loadInBlock(&state, block);
            albionCBC(&state);
            albionBlockEnc(&state);
            albionCBCSaveEnc(&state);
            loadOutBlock(&state, block);
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

void * albion_cbc_decrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
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

    struct albionState state;
    state.blocklen = 32;
    state.rounds = 14;
    int count = 0;
    uint8_t block[32] = {0};
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
        fseek(infile, (mac_length + nonce_length + key_length +  crypto_box_SEALBYTES + crypto_sign_BYTES), SEEK_SET);
        loadInIVALBI(&state, iv);
        albiongenRoundKeys(&state, key, key_length);
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
                loadInBlock(&state, block);
                albionCBCSaveDec(&state);
                albionBlockDec(&state);
                albionCBC(&state);
                albionCBCSaveDec2(&state);
                loadOutBlock(&state, block);
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
