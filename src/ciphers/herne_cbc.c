/* KryptoMagick Herne Cipher [2021] */

int herneIP[32] = {10, 0, 31, 20, 2, 22, 1, 6, 17, 4, 23, 13, 26, 8, 21, 14, 28, 7, 27, 25, 11, 16, 5, 30, 9, 19, 15, 3, 29, 18, 24, 12};

uint32_t herneC0[8] = {0xd419dd28, 0xe2be508d, 0xc7d77bcd, 0xf92730ad, 0xba943336, 0xd9700b94, 0xe89147b7, 0xd835c940};

struct herneState {
    uint32_t K[32][8];
    uint32_t B[8];
    uint8_t M[32];
    uint32_t PRK[8];
    uint32_t POK[8];
    uint32_t last[8];
    uint32_t next[8];
    int rounds;
    int blocklen;
};

struct herneksaState {
    uint32_t r[16];
    uint32_t o;
};

uint32_t herne_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t herne_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void *herne_F(struct herneksaState *state) {
    int r;
    uint32_t tmp[16];
    memcpy(tmp, state->r, 16*(sizeof(uint32_t)));
    for (r = 0; r < 16; r++) {
        state->r[0] += state->r[4];
        state->r[1] = herne_rotl((state->r[1] ^ state->r[10]), 22);
        state->r[2] += state->r[12];
        state->r[3] = herne_rotl((state->r[3] ^ state->r[8]), 25);
        state->r[4] += state->r[5];
        state->r[5] = herne_rotl((state->r[5] ^ state->r[2]), 12);
        state->r[6] += state->r[7];
        state->r[7] = herne_rotl((state->r[7] ^ state->r[0]), 29);
        state->r[8] += state->r[9];
        state->r[9] = herne_rotl((state->r[9] ^ state->r[14]), 2);
        state->r[10] += state->r[11];
        state->r[11] = herne_rotl((state->r[11] ^ state->r[1]), 7);
        state->r[12] += state->r[13];
        state->r[13] = herne_rotl((state->r[13] ^ state->r[15]), 13);
        state->r[14] += state->r[3];
        state->r[15] = herne_rotl((state->r[15] ^ state->r[6]), 9);
    }
    state->o = 0;
    for (r = 0; r < 16; r++) {
        state->r[r] += tmp[r];
        state->o ^= state->r[r];
    }
}

void hernegenRoundKeys(struct herneState * state, unsigned char * key, int keylen) {
    struct herneksaState kstate;
    int c = 0;
    int i;
    int q;
    memset(&kstate.r, 0, 16*sizeof(uint32_t));
    memset(&kstate.o, 0, sizeof(uint32_t));
    kstate.r[8] = herneC0[0];
    kstate.r[9] = herneC0[1];
    kstate.r[10] = herneC0[2];
    kstate.r[11] = herneC0[3];
    kstate.r[12] = herneC0[4];
    kstate.r[13] = herneC0[5];
    kstate.r[14] = herneC0[6];
    kstate.r[15] = herneC0[7];
    for (i = 0; i < (keylen / 4); i++) {
        kstate.r[i] ^= (key[c] << 24) + (key[c+1] << 16) + (key[c+2] << 8) + key[c+3];
        c += 4;
    }
    for (i = 0; i < state->rounds; i++) {
        for (q = 0; q < 8; q++) {
            herne_F(&kstate);
            state->K[i][q] = 0;
	    state->K[i][q] = kstate.o;
        }
    }
    for (q = 0; q < 8; q++) {
        herne_F(&kstate);
        state->POK[q] = 0;
        state->POK[q] = kstate.o;
    }
    for (q = 0; q < 8; q++) {
        herne_F(&kstate);
        state->PRK[q] = 0;
        state->PRK[q] = kstate.o;
    }
}

void loadInIVHRN(struct herneState *state, unsigned char *iv) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
       state->last[q] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
       c += 4;
    }
}

void loadInBlockHRN(struct herneState *state, uint8_t *block) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
        state->B[q] = (block[c] << 24) + (block[c+1] << 16) + (block[c+2] << 8) + block[c+3];
        c += 4;
    }
}

void loadOutBlockHRN(struct herneState *state, uint8_t *block) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
        block[c] = state->B[q] >> 24; 
        block[c+1] = state->B[q] >> 16; 
        block[c+2] = state->B[q] >> 8; 
        block[c+3] = state->B[q]; 
        c += 4;
    }
}

void IPHRN(struct herneState *state) {
    state->M[10] = state->B[0] >> 24;
    state->M[0] = state->B[0] >> 16;
    state->M[31] = state->B[0] >> 8;
    state->M[20] = state->B[0];
    state->M[2] = state->B[1] >> 24;
    state->M[22] = state->B[1] >> 16;
    state->M[1] = state->B[1] >> 8;
    state->M[6] = state->B[1];
    state->M[17] = state->B[2] >> 24;
    state->M[4] = state->B[2] >> 16;
    state->M[23] = state->B[2] >> 8;
    state->M[13] = state->B[2];
    state->M[26] = state->B[3] >> 24;
    state->M[8] = state->B[3] >> 16;
    state->M[21] = state->B[3] >> 8;
    state->M[14] = state->B[3];
    state->M[28] = state->B[4] >> 24;
    state->M[7] = state->B[4] >> 16;
    state->M[27] = state->B[4] >> 8;
    state->M[25] = state->B[4];
    state->M[11] = state->B[5] >> 24;
    state->M[16] = state->B[5] >> 16;
    state->M[5] = state->B[5] >> 8;
    state->M[30] = state->B[5];
    state->M[9] = state->B[6] >> 24;
    state->M[19] = state->B[6] >> 16;
    state->M[15] = state->B[6] >> 8;
    state->M[3] = state->B[6];
    state->M[29] = state->B[7] >> 24;
    state->M[18] = state->B[7] >> 16;
    state->M[24] = state->B[7] >> 8;
    state->M[12] = state->B[7];

    state->B[0] = (state->M[0] << 24) + (state->M[1] << 16) + (state->M[2] << 8) + state->M[3];
    state->B[1] = (state->M[4] << 24) + (state->M[5] << 16) + (state->M[6] << 8) + state->M[7];
    state->B[2] = (state->M[8] << 24) + (state->M[9] << 16) + (state->M[10] << 8) + state->M[11];
    state->B[3] = (state->M[12] << 24) + (state->M[13] << 16) + (state->M[14] << 8) + state->M[15];
    state->B[4] = (state->M[16] << 24) + (state->M[17] << 16) + (state->M[18] << 8) + state->M[19];
    state->B[5] = (state->M[20] << 24) + (state->M[21] << 16) + (state->M[22] << 8) + state->M[23];
    state->B[6] = (state->M[24] << 24) + (state->M[25] << 16) + (state->M[26] << 8) + state->M[27];
    state->B[7] = (state->M[28] << 24) + (state->M[29] << 16) + (state->M[30] << 8) + state->M[31];
    
}

void InvIPHRN(struct herneState *state) {
    state->M[0] = state->B[0] >> 24;
    state->M[1] = state->B[0] >> 16;
    state->M[2] = state->B[0] >> 8;
    state->M[3] = state->B[0];
    state->M[4] = state->B[1] >> 24;
    state->M[5] = state->B[1] >> 16;
    state->M[6] = state->B[1] >> 8;
    state->M[7] = state->B[1];
    state->M[8] = state->B[2] >> 24;
    state->M[9] = state->B[2] >> 16;
    state->M[10] = state->B[2] >> 8;
    state->M[11] = state->B[2];
    state->M[12] = state->B[3] >> 24;
    state->M[13] = state->B[3] >> 16;
    state->M[14] = state->B[3] >> 8;
    state->M[15] = state->B[3];
    state->M[16] = state->B[4] >> 24;
    state->M[17] = state->B[4] >> 16;
    state->M[18] = state->B[4] >> 8;
    state->M[19] = state->B[4];
    state->M[20] = state->B[5] >> 24;
    state->M[21] = state->B[5] >> 16;
    state->M[22] = state->B[5] >> 8;
    state->M[23] = state->B[5];
    state->M[24] = state->B[6] >> 24;
    state->M[25] = state->B[6] >> 16;
    state->M[26] = state->B[6] >> 8;
    state->M[27] = state->B[6];
    state->M[28] = state->B[7] >> 24;
    state->M[29] = state->B[7] >> 16;
    state->M[30] = state->B[7] >> 8;
    state->M[31] = state->B[7];

    state->B[0] = (state->M[10] << 24) + (state->M[0] << 16) + (state->M[31] << 8) + state->M[20];
    state->B[1] = (state->M[2] << 24) + (state->M[22] << 16) + (state->M[1] << 8) + state->M[6];
    state->B[2] = (state->M[17] << 24) + (state->M[4] << 16) + (state->M[23] << 8) + state->M[13];
    state->B[3] = (state->M[26] << 24) + (state->M[8] << 16) + (state->M[21] << 8) + state->M[14];
    state->B[4] = (state->M[28] << 24) + (state->M[7] << 16) + (state->M[27] << 8) + state->M[25];
    state->B[5] = (state->M[11] << 24) + (state->M[16] << 16) + (state->M[5] << 8) + state->M[30];
    state->B[6] = (state->M[9] << 24) + (state->M[19] << 16) + (state->M[15] << 8) + state->M[3];
    state->B[7] = (state->M[29] << 24) + (state->M[18] << 16) + (state->M[24] << 8) + state->M[12];
}

void IMHRN(struct herneState *state) {
    state->B[0] += state->B[4];
    state->B[1] += state->B[5];
    state->B[2] += state->B[6];
    state->B[3] += state->B[7];
    state->B[4] += state->B[0];
    state->B[5] += state->B[1];
    state->B[6] += state->B[2];
    state->B[7] += state->B[3];
}

void InvIMHRN(struct herneState *state) {
    state->B[7] -= state->B[3];
    state->B[6] -= state->B[2];
    state->B[5] -= state->B[1];
    state->B[4] -= state->B[0];
    state->B[3] -= state->B[7];
    state->B[2] -= state->B[6];
    state->B[1] -= state->B[5];
    state->B[0] -= state->B[4];
}

void CNF8HRN(struct herneState *state) {
    state->B[0] += state->B[6];
    state->B[0] = herne_rotl(state->B[0], 7);
    state->B[0] ^= state->B[2];
    state->B[1] += state->B[7];
    state->B[1] = herne_rotr(state->B[1], 11);
    state->B[1] ^= state->B[3];
    state->B[2] += state->B[0];
    state->B[2] = herne_rotl(state->B[2], 13);
    state->B[2] ^= state->B[4];
    state->B[3] += state->B[5];
    state->B[3] = herne_rotr(state->B[3], 19);
    state->B[3] ^= state->B[1];
    state->B[4] += state->B[2];
    state->B[4] = herne_rotl(state->B[4], 23);
    state->B[4] ^= state->B[0];
    state->B[5] += state->B[1];
    state->B[5] = herne_rotr(state->B[5], 29);
    state->B[5] ^= state->B[7];
    state->B[6] += state->B[4];
    state->B[6] = herne_rotl(state->B[6], 31);
    state->B[6] ^= state->B[2];
    state->B[7] += state->B[3];
    state->B[7] = herne_rotr(state->B[7], 2);
    state->B[7] ^= state->B[5];
}

void InvCNF8HRN(struct herneState *state) {
    state->B[7] ^= state->B[5];
    state->B[7] = herne_rotl(state->B[7], 2);
    state->B[7] -= state->B[3];
    state->B[6] ^= state->B[2];
    state->B[6] = herne_rotr(state->B[6], 31);
    state->B[6] -= state->B[4];
    state->B[5] ^= state->B[7];
    state->B[5] = herne_rotl(state->B[5], 29);
    state->B[5] -= state->B[1];
    state->B[4] ^= state->B[0];
    state->B[4] = herne_rotr(state->B[4], 23);
    state->B[4] -= state->B[2];
    state->B[3] ^= state->B[1];
    state->B[3] = herne_rotl(state->B[3], 19);
    state->B[3] -= state->B[5];
    state->B[2] ^= state->B[4];
    state->B[2] = herne_rotr(state->B[2], 13);
    state->B[2] -= state->B[0];
    state->B[1] ^= state->B[3];
    state->B[1] = herne_rotl(state->B[1], 11);
    state->B[1] -= state->B[7];
    state->B[0] ^= state->B[2];
    state->B[0] = herne_rotr(state->B[0], 7);
    state->B[0] -= state->B[6];
}

void Rotate8HRN(struct herneState *state) {
    herne_rotl(state->B[0], 1);
    herne_rotl(state->B[1], 8);
    herne_rotl(state->B[2], 12);
    herne_rotl(state->B[3], 16);
    herne_rotl(state->B[4], 19);
    herne_rotl(state->B[5], 24);
    herne_rotl(state->B[6], 29);
    herne_rotl(state->B[7], 31);
}

void InvRotate8HRN(struct herneState *state) {
    herne_rotr(state->B[0], 1);
    herne_rotr(state->B[1], 8);
    herne_rotr(state->B[2], 12);
    herne_rotr(state->B[3], 16);
    herne_rotr(state->B[4], 19);
    herne_rotr(state->B[5], 24);
    herne_rotr(state->B[6], 29);
    herne_rotr(state->B[7], 31);
}

void Mix8HRN(struct herneState *state) {
    state->B[0] += state->B[4];
    state->B[4] += state->B[1];
    state->B[1] += state->B[5];
    state->B[5] += state->B[2];
    state->B[2] += state->B[6];
    state->B[6] += state->B[3];
    state->B[3] += state->B[7];
    state->B[7] += state->B[0];
}

void InvMix8HRN(struct herneState *state) {
    state->B[7] -= state->B[0];
    state->B[3] -= state->B[7];
    state->B[6] -= state->B[3];
    state->B[2] -= state->B[6];
    state->B[5] -= state->B[2];
    state->B[1] -= state->B[5];
    state->B[4] -= state->B[1];
    state->B[0] -= state->B[4];
}

void AddRoundKeyHRN(struct herneState *state, int r) {
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->K[r][q];
    }
}

void AddPRKHRN(struct herneState *state) {
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->PRK[q];
    }
}

void AddPOKHRN(struct herneState *state) {
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->POK[q];
    }
}

uint64_t herneBlockEnc(struct herneState * state) {
    AddPRKHRN(state);
    IPHRN(state);
    IMHRN(state);
    for (int r = 0; r < state->rounds; r++) {
        CNF8HRN(state);
        Rotate8HRN(state);
        Mix8HRN(state);
        AddRoundKeyHRN(state, r);
    }
    AddPOKHRN(state);
}

uint64_t herneBlockDec(struct herneState * state) {
    AddPOKHRN(state);
    for (int r = state->rounds - 1; r != -1; r--) {
        AddRoundKeyHRN(state, r);
        InvMix8HRN(state);
        InvRotate8HRN(state);
        InvCNF8HRN(state);
    }
    InvIMHRN(state);
    InvIPHRN(state);
    AddPRKHRN(state);
}

void herneCBC(struct herneState *state) {
    int c = 0;
    for (int q = 0; q < 8; q++) {
        state->B[q] ^= state->last[q];
    }
}

void herneCBCSaveEnc(struct herneState *state) {
    memcpy(state->last, state->B, 8*(sizeof(uint32_t)));
}

void herneCBCSaveDec(struct herneState *state) {
    memcpy(state->next, state->B, 8*(sizeof(uint32_t)));
}

void herneCBCSaveDec2(struct herneState *state) {
    memcpy(state->last, state->next, 8*(sizeof(uint32_t)));
}

void * herne_cbc_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int mac_ivlength, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int bufsize, unsigned char * passphrase) {
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
    unsigned char maciv[mac_ivlength];
    amagus_random(&maciv, mac_ivlength);
    unsigned char mac[mac_length];
    memset(mac, 0, mac_length);
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
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(maciv, 1, mac_ivlength, outfile);
    fwrite(S, 1, crypto_sign_BYTES, outfile);
    fwrite(passwctxt, 1, crypto_box_SEALBYTES + key_length, outfile);
    fwrite(iv, 1, nonce_length, outfile);

    struct herneState state;
    struct belethState bltstate;
    state.blocklen = 32;
    state.rounds = 32;
    uint8_t block[32] = {0};
    int blocksize = 32;
    uint64_t blocks = datalen / bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
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
    loadInIVHRN(&state, iv);
    hernegenRoundKeys(&state, key, key_length);
    belethAuthInit(&bltstate, mac_key, key_length, maciv, mac_ivlength);
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
            loadInBlockHRN(&state, block);
            herneCBC(&state);
            herneBlockEnc(&state);
            herneCBCSaveEnc(&state);
            loadOutBlockHRN(&state, block);
            belethAuthUpdate(&bltstate, block);
            for (int x = 0; x < state.blocklen; x++) {
                buffer[c+x] = (unsigned char)block[x];
            }
            c += state.blocklen;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    belethAuthFinal(&bltstate);
    fseek(outfile, 0, SEEK_SET);
    fwrite(bltstate.MAC, 1, mac_length, outfile);
    fclose(infile);
    fclose(outfile);
}

void * herne_cbc_decrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int mac_ivlength, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
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
    unsigned char maciv[mac_ivlength];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *passtmp[(crypto_box_SEALBYTES + key_length)];
    unsigned char S[crypto_sign_BYTES];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    fread(mac, 1, mac_length, infile);
    fread(maciv, 1, mac_ivlength, infile);
    fread(S, 1, crypto_sign_BYTES, infile);
    fread(passtmp, 1, crypto_box_SEALBYTES + key_length, infile);
    fread(iv, 1, nonce_length, infile);
    datalen = datalen - key_length - mac_length - mac_ivlength - nonce_length - crypto_box_SEALBYTES - crypto_sign_BYTES;
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

    struct herneState state;
    struct belethState bltstate;
    state.blocklen = 32;
    state.rounds = 32;
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
    belethAuthInit(&bltstate, mac_key, key_length, maciv, mac_ivlength);
    outfile = fopen(outputfile, "wb");
    infile = fopen(inputfile, "rb");
    fseek(infile, (mac_length + mac_ivlength + nonce_length + key_length +  crypto_box_SEALBYTES + crypto_sign_BYTES), SEEK_SET);
    loadInIVHRN(&state, iv);
    hernegenRoundKeys(&state, key, key_length);
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
            belethAuthUpdate(&bltstate, block);
            loadInBlockHRN(&state, block);
            herneCBCSaveDec(&state);
            herneBlockDec(&state);
            herneCBC(&state);
            herneCBCSaveDec2(&state);
            loadOutBlockHRN(&state, block);
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
    belethAuthFinal(&bltstate);
    if (belethAuthVerify(&bltstate, mac) == 1) {
        printf("Error: Message has been tampered with.\n");
    };
    fclose(infile);
    fclose(outfile);
}
