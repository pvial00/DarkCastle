#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct spock_state {
    uint32_t Ka[48];
    uint32_t Kb[48];
    uint32_t d[48][4];
    int rounds;
};

uint32_t spock_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t spock_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void roundF(struct spock_state *state, uint32_t *xla, uint32_t *xlb, uint32_t *xra, uint32_t *xrb) {
    uint32_t a, b, c, d;
    int r;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (r = 0; r < state->rounds; r++) {
        a = spock_rotr(a, 8);
	a += d;
        a ^= state->Ka[r];
        b = spock_rotr(b, 7);
	b += c;
        b ^= state->Kb[r];
	c = spock_rotl(c, 2);
	c ^= b;
	d = spock_rotl(d, 3);
	d ^= a;
	a += b;
	b += a;
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

void roundB(struct spock_state *state, uint32_t *xla, uint32_t *xlb, uint32_t *xra, uint32_t *xrb) {
    uint32_t a, b, c, d;
    int r;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (r = state->rounds; r --> 0;) {
	d -= state->d[r][3];
	c -= state->d[r][2];
	b -= state->d[r][1];
	a -= state->d[r][0];
	b -= a;
	a -= b;
	d ^= a;
	d = spock_rotr(d, 3);
	c ^= b;
	c = spock_rotr(c, 2);
        b ^= state->Kb[r];
	b -= c;
        b = spock_rotl(b, 7);
        a ^= state->Ka[r];
	a -= d;
        a = spock_rotl(a, 8);
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void spock_ksa(struct spock_state *state, unsigned char * keyp, int keylen) {
    uint32_t temp = 0x00000001;
    struct spock_state tempstate;
    int m = 0;
    int b, i, r, x;
    uint32_t k[8];
    memset(k, 0, 8*sizeof(uint32_t));
    memset(state->Ka, 0, state->rounds*sizeof(uint32_t));
    memset(state->Kb, 0, state->rounds*sizeof(uint32_t));
    memset(tempstate.Ka, 0, state->rounds*sizeof(uint32_t));
    memset(tempstate.Kb, 0, state->rounds*sizeof(uint32_t));
    memset(state->d, 0, 4*(state->rounds*sizeof(uint32_t)));
    memset(tempstate.d, 0, 4*(state->rounds*sizeof(uint32_t)));
    for (i = 0; i < 8; i++) {
        k[i] = 0;
        k[i] = (keyp[m] << 24) + (keyp[m+1] << 16) + (keyp[m+2] << 8) + keyp[m+3];
        m += 4;
    }
    
    for (r = 0; r < state->rounds; r++) {
        k[0] = spock_rotr(k[0], 8);
        k[0] += k[4];
        k[0] ^= k[6];
        k[1] = spock_rotr(k[1], 7);
        k[1] += k[2];
        k[1] ^= k[0];
        k[2] = spock_rotr(k[2], 2);
        k[2] ^= k[1];
        k[3] = spock_rotl(k[3], 3);
        k[3] ^= k[5];
        k[3] += k[7];

        k[4] = spock_rotr(k[5], 8);
        k[4] += k[3];
        k[4] ^= k[2];
        k[5] = spock_rotr(k[5], 7);
        k[5] += k[0];
        k[5] ^= k[6];
        k[6] = spock_rotr(k[6], 2);
        k[6] ^= k[2];
        k[7] = spock_rotl(k[7], 3);
        k[7] ^= k[4];
        k[7] += k[5];
        for (i = 0; i < 8; i++) {
            tempstate.Ka[r] ^= (uint32_t)k[i];
        }
    }
    for (r = 0; r < state->rounds; r++) {
        k[0] = spock_rotr(k[0], 8);
        k[0] += k[4];
        k[0] ^= k[6];
        k[1] = spock_rotr(k[1], 7);
        k[1] += k[2];
        k[1] ^= k[0];
        k[2] = spock_rotr(k[2], 2);
        k[2] ^= k[1];
        k[3] = spock_rotl(k[3], 3);
        k[3] ^= k[5];
        k[3] += k[7];

        k[4] = spock_rotr(k[5], 8);
        k[4] += k[3];
        k[4] ^= k[2];
        k[5] = spock_rotr(k[5], 7);
        k[5] += k[0];
        k[5] ^= k[6];
        k[6] = spock_rotr(k[6], 2);
        k[6] ^= k[2];
        k[7] = spock_rotl(k[7], 3);
        k[7] ^= k[4];
        k[7] += k[5];
        for (i = 0; i < 8; i++) {
            tempstate.Kb[r] ^= (uint32_t)k[i];
        }
    }
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < 4; i++) {
            k[0] = spock_rotr(k[0], 8);
            k[0] += k[4];
            k[0] ^= k[6];
            k[1] = spock_rotr(k[1], 7);
            k[1] += k[2];
            k[1] ^= k[0];
            k[2] = spock_rotr(k[2], 2);
            k[2] ^= k[1];
            k[3] = spock_rotl(k[3], 3);
            k[3] ^= k[5];
            k[3] += k[7];

            k[4] = spock_rotr(k[5], 8);
            k[4] += k[3];
            k[4] ^= k[2];
            k[5] = spock_rotr(k[5], 7);
            k[5] += k[0];
            k[5] ^= k[6];
            k[6] = spock_rotr(k[6], 2);
            k[6] ^= k[2];
            k[7] = spock_rotl(k[7], 3);
            k[7] ^= k[4];
            k[7] += k[5];
            for (x = 0; x < 8; x++) {
	        tempstate.d[r][i] ^= (uint32_t)k[x];
            }
        }
    }
    for (r = 0; r < state->rounds; r++) {
        k[0] = spock_rotr(k[0], 8);
        k[0] += k[4];
        k[0] ^= k[6];
        k[1] = spock_rotr(k[1], 7);
        k[1] += k[2];
        k[1] ^= k[0];
        k[2] = spock_rotr(k[2], 2);
        k[2] ^= k[1];
        k[3] = spock_rotl(k[3], 3);
        k[3] ^= k[5];
        k[3] += k[7];

        k[4] = spock_rotr(k[5], 8);
        k[4] += k[3];
        k[4] ^= k[2];
        k[5] = spock_rotr(k[5], 7);
        k[5] += k[0];
        k[5] ^= k[6];
        k[6] = spock_rotr(k[6], 2);
        k[6] ^= k[2];
        k[7] = spock_rotl(k[7], 3);
        k[7] ^= k[4];
        k[7] += k[5];
        for (i = 0; i < 8; i++) {
            state->Ka[r] ^= (uint32_t)k[i];
        }
        k[0] = spock_rotr(k[0], 8);
        k[0] += k[4];
        k[0] ^= k[6];
        k[1] = spock_rotr(k[1], 7);
        k[1] += k[2];
        k[1] ^= k[0];
        k[2] = spock_rotr(k[2], 2);
        k[2] ^= k[1];
        k[3] = spock_rotl(k[3], 3);
        k[3] ^= k[5];
        k[3] += k[7];

        k[4] = spock_rotr(k[5], 8);
        k[4] += k[3];
        k[4] ^= k[2];
        k[5] = spock_rotr(k[5], 7);
        k[5] += k[0];
        k[5] ^= k[6];
        k[6] = spock_rotr(k[6], 2);
        k[6] ^= k[2];
        k[7] = spock_rotl(k[7], 3);
        k[7] ^= k[4];
        k[7] += k[5];
        for (i = 0; i < 8; i++) {
            state->Kb[r] ^= (uint32_t)k[i];
        }
    }
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < 4; i++) {
            k[0] = spock_rotr(k[0], 8);
            k[0] += k[4];
            k[0] ^= k[6];
            k[1] = spock_rotr(k[1], 7);
            k[1] += k[2];
            k[1] ^= k[0];
            k[2] = spock_rotr(k[2], 2);
            k[2] ^= k[1];
            k[3] = spock_rotl(k[3], 3);
            k[3] ^= k[5];
            k[3] += k[7];

            k[4] = spock_rotr(k[5], 8);
            k[4] += k[3];
            k[4] ^= k[2];
            k[5] = spock_rotr(k[5], 7);
            k[5] += k[0];
            k[5] ^= k[6];
            k[6] = spock_rotr(k[6], 2);
            k[6] ^= k[2];
            k[7] = spock_rotl(k[7], 3);
            k[7] ^= k[4];
            k[7] += k[5];
            for (x = 0; x < 8; x++) {
                state->d[r][i] ^= (uint32_t)k[x];
            }
        }
    }
}

void * spock_cbc_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    load_pkfile(keyfile1, &ctx);
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &Sctx);
    unsigned char *password[password_len];
    amagus_random(password, password_len);
    BIGNUM *tmp;
    BIGNUM *BNctxt;
    BIGNUM *S;
    tmp = BN_new();
    BNctxt = BN_new();
    S = BN_new();
    unsigned char *X[mask_bytes];
    unsigned char *Y[mask_bytes];
    amagus_random(Y, mask_bytes);
    mypad_encrypt(password, password_len, X, mask_bytes, Y);
    BN_bin2bn(X, mask_bytes, tmp);
    cloak(&ctx, BNctxt, tmp);
    sign(&Sctx, S, BNctxt);
    int ctxtbytes = BN_num_bytes(BNctxt);
    unsigned char *password_ctxt[ctxtbytes];
    BN_bn2bin(BNctxt, password_ctxt);
    int Sbytes = BN_num_bytes(S);
    unsigned char *sign_ctxt[Sbytes];
    BN_bn2bin(S, sign_ctxt);

    int blocksize = 16;
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
    manja_kdf(password, password_len, key, key_length, kdf_salt, salt_len, kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(password_ctxt, 1, mask_bytes, outfile);
    fwrite(Y, 1, mask_bytes, outfile);
    fwrite(sign_ctxt, 1, Sbytes, outfile);
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(iv, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);

    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct spock_state state;
    int iv_length = 16;
    state.rounds = 48;
    int c = 0;
    spock_ksa(&state, keyprime, key_length);
    int v = 16;
    uint64_t i = 0;
    int x,  b, ii, r;
    int t = 0;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    for (int i = 0; i < 4; i++) {
        last[i] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
        c += 4;
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
        int bblocks = bufsize / 16;
        int bextra = bufsize % 16;
        if (bextra != 0) {
            bblocks += 1;
        }
        for (b = 0; b < bblocks; b++) {
            block[0] = (buffer[c] << 24) + (buffer[c+1] << 16) + (buffer[c+2] << 8) + buffer[c+3];
            block[1] = (buffer[c+4] << 24) + (buffer[c+5] << 16) + (buffer[c+6] << 8) + buffer[c+7];
            block[2] = (buffer[c+8] << 24) + (buffer[c+9] << 16) + (buffer[c+10] << 8) + buffer[c+11];
            block[3] = (buffer[c+12] << 24) + (buffer[c+13] << 16) + (buffer[c+14] << 8) + buffer[c+15];
            for (r = 0; r < 4; r++) {
                block[r] = block[r] ^ last[r];
            }
            roundF(&state, &block[0], &block[1], &block[2], &block[3]);
            for (int r = 0; r < 4; r++) {
                last[r] = block[r];
            }
            buffer[c+3] = (block[0] & 0x000000FF);
            buffer[c+2] = (block[0] & 0x0000FF00) >> 8;
            buffer[c+1] = (block[0] & 0x00FF0000) >> 16;
            buffer[c] = (block[0] & 0xFF000000) >> 24;
            buffer[c+7] = (block[1] & 0x000000FF);
            buffer[c+6] = (block[1] & 0x0000FF00) >> 8;
            buffer[c+5] = (block[1] & 0x00FF0000) >> 16;
            buffer[c+4] = (block[1] & 0xFF000000) >> 24;
            buffer[c+11] = (block[2] & 0x000000FF);
            buffer[c+10] = (block[2] & 0x0000FF00) >> 8;
            buffer[c+9] = (block[2] & 0x00FF0000) >> 16;
            buffer[c+8] = (block[2] & 0xFF000000) >> 24;
            buffer[c+15] = (block[3] & 0x000000FF);
            buffer[c+14] = (block[3] & 0x0000FF00) >> 8;
            buffer[c+13] = (block[3] & 0x00FF0000) >> 16;
            buffer[c+12] = (block[3] & 0xFF000000) >> 24;
            c += 16;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * spock_cbc_decrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    struct qloq_ctx ctx;
    BIGNUM *tmp;
    BIGNUM *tmpS;
    BIGNUM *BNctxt;
    tmp = BN_new();
    tmpS = BN_new();
    BNctxt = BN_new();
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &ctx);
    load_pkfile(keyfile2, &ctx);

    int blocksize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *passtmp[mask_bytes];
    unsigned char *Ytmp[mask_bytes];
    unsigned char *signtmp[mask_bytes];
    unsigned char *kwnonce[keywrap_ivlen];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen - mask_bytes - mask_bytes - mask_bytes;
    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(passtmp, 1, mask_bytes, infile);
    fread(Ytmp, 1, mask_bytes, infile);
    fread(signtmp, 1, mask_bytes, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    BN_bin2bn(passtmp, mask_bytes, tmp);
    decloak(&ctx, BNctxt, tmp);
    int ctxtbytes = BN_num_bytes(BNctxt);
    unsigned char password[ctxtbytes];
    BN_bn2bin(BNctxt, password);
    unsigned char *passkey[password_len];
    mypad_decrypt(passtmp, password, ctxtbytes, Ytmp);
    memcpy(passkey, passtmp, password_len);
    BN_bin2bn(signtmp, mask_bytes, tmpS);
    if (verify(&ctx, tmp, BNctxt) != 0) {
        printf("Error: Signature verification failed. Message is not authentic.\n");
        exit(2);
    }
    manja_kdf(passkey, password_len, key, key_length, kdf_salt, salt_len, kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    uint8_t k[16];
    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct spock_state state;
    int iv_length = 16;
    state.rounds = 48;
    int c = 0;
    spock_ksa(&state, keyprime, key_length);
    uint64_t i = 0;
    int x, b, ii, r;
    int t = 0;
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
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length + (mask_bytes*3)), SEEK_SET);
        c = 0;
        for (int i = 0; i < 4; i++) {
            last[i] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
            c += 4;
        }
        for (i = 0; i < (blocks); i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / 16;
            int bextra = bufsize % 16;
            if (bextra != 0) {
                bblocks += 1;
            }
            for (b = 0; b < bblocks; b++) {
                block[0] = (buffer[c] << 24) + (buffer[c+1] << 16) + (buffer[c+2] << 8) + buffer[c+3];
                block[1] = (buffer[c+4] << 24) + (buffer[c+5] << 16) + (buffer[c+6] << 8) + buffer[c+7];
                block[2] = (buffer[c+8] << 24) + (buffer[c+9] << 16) + (buffer[c+10] << 8) + buffer[c+11];
                block[3] = (buffer[c+12] << 24) + (buffer[c+13] << 16) + (buffer[c+14] << 8) + buffer[c+15];
                for (r = 0; r < 4; r++) {
                    next[r] = block[r];
                }
                roundB(&state, &block[0], &block[1], &block[2], &block[3]);
                for (r = 0; r < 4; r++) {
                    block[r] = block[r] ^ last[r];
                    last[r] = next[r];
                }
                buffer[c+3] = (block[0] & 0x000000FF);
                buffer[c+2] = (block[0] & 0x0000FF00) >> 8;
                buffer[c+1] = (block[0] & 0x00FF0000) >> 16;
                buffer[c] = (block[0] & 0xFF000000) >> 24;
                buffer[c+7] = (block[1] & 0x000000FF);
                buffer[c+6] = (block[1] & 0x0000FF00) >> 8;
                buffer[c+5] = (block[1] & 0x00FF0000) >> 16;
                buffer[c+4] = (block[1] & 0xFF000000) >> 24;
                buffer[c+11] = (block[2] & 0x000000FF);
                buffer[c+10] = (block[2] & 0x0000FF00) >> 8;
                buffer[c+9] = (block[2] & 0x00FF0000) >> 16;
                buffer[c+8] = (block[2] & 0xFF000000) >> 24;
                buffer[c+15] = (block[3] & 0x000000FF);
                buffer[c+14] = (block[3] & 0x0000FF00) >> 8;
                buffer[c+13] = (block[3] & 0x00FF0000) >> 16;
                buffer[c+12] = (block[3] & 0xFF000000) >> 24;
                c += 16;
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
