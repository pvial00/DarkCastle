#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void * zander2_ofb_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
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

    bufsize = 16;
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
    struct zander_state state;
    uint64_t xl;
    uint64_t xr;
    uint8_t output[16];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    uint64_t blocks = datalen / zblocklen;
    int extra = datalen % zblocklen;
    uint64_t i;
    int c = 0;
    int b;
    int l = 16;
    if (extra != 0) {
        blocks += 1;
    }
    zgen_subkeys(&state, keyprime, key_length, iv, nonce_length, z2rounds);
    zgen_sbox(&state, keyprime, key_length);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1) && (extra != 0)) {
            l = extra;
	}

        zblock_encrypt(&state, &xl, &xr);


        output[0] = (xl & 0xFF00000000000000) >> 56;
        output[1] = (xl & 0x00FF000000000000) >> 48;
        output[2] = (xl & 0x0000FF0000000000) >> 40;
        output[3] = (xl & 0x000000FF00000000) >> 32;
        output[4] = (xl & 0x00000000FF000000) >> 24;
        output[5] = (xl & 0x0000000000FF0000) >> 16;
        output[6] = (xl & 0x000000000000FF00) >> 8;
        output[7] = (xl & 0x00000000000000FF);
        output[8] = (xr & 0xFF00000000000000) >> 56;
        output[9] = (xr & 0x00FF000000000000) >> 48;
        output[10] = (xr & 0x0000FF0000000000) >> 40;
        output[11] = (xr & 0x000000FF00000000) >> 32;
        output[12] = (xr & 0x00000000FF000000) >> 24;
        output[13] = (xr & 0x0000000000FF0000) >> 16;
        output[14] = (xr & 0x000000000000FF00) >> 8;
        output[15] = (xr & 0x00000000000000FF);
        fread(&buffer, 1, l, infile);
        for (b = 0; b < l; b++) {
            buffer[b] = buffer[b] ^ output[b];
        }
        fwrite(buffer, 1, l, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * zander2_ofb_decrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) {
    struct qloq_ctx ctx;
    BIGNUM *tmp;
    BIGNUM *tmpS;
    BIGNUM *BNctxt;
    tmp = BN_new();
    tmpS = BN_new();
    BNctxt = BN_new();
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &ctx);
    load_pkfile(keyfile2, &ctx);

    bufsize = 16;
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
    struct zander_state state;
    uint64_t xl;
    uint64_t xr;
    uint8_t output[16];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    uint64_t blocks = datalen / zblocklen;
    int extra = datalen % zblocklen;
    int c = 0;
    int i, b;
    int l = 16;
    if (extra != 0) {
        blocks += 1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length + (mask_bytes*3)), SEEK_SET);
        zgen_subkeys(&state, keyprime, key_length, iv, nonce_length, z2rounds);
        zgen_sbox(&state, keyprime, key_length);
        for (i = 0; i < blocks; i++) {
	    if ((i == (blocks - 1)) && (extra != 0)) {
                l = extra;
	    }

            zblock_encrypt(&state, &xl, &xr);


            output[0] = (xl & 0xFF00000000000000) >> 56;
            output[1] = (xl & 0x00FF000000000000) >> 48;
            output[2] = (xl & 0x0000FF0000000000) >> 40;
            output[3] = (xl & 0x000000FF00000000) >> 32;
            output[4] = (xl & 0x00000000FF000000) >> 24;
            output[5] = (xl & 0x0000000000FF0000) >> 16;
            output[6] = (xl & 0x000000000000FF00) >> 8;
            output[7] = (xl & 0x00000000000000FF);
            output[8] = (xr & 0xFF00000000000000) >> 56;
            output[9] = (xr & 0x00FF000000000000) >> 48;
            output[10] = (xr & 0x0000FF0000000000) >> 40;
            output[11] = (xr & 0x000000FF00000000) >> 32;
            output[12] = (xr & 0x00000000FF000000) >> 24;
            output[13] = (xr & 0x0000000000FF0000) >> 16;
            output[14] = (xr & 0x000000000000FF00) >> 8;
            output[15] = (xr & 0x00000000000000FF);
            fread(&buffer, 1, l, infile);
            for (b = 0; b < l; b++) {
                buffer[b] = buffer[b] ^ output[b];
            }
            fwrite(buffer, 1, l, outfile);
        }
        fclose(infile);
        fclose(outfile);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
