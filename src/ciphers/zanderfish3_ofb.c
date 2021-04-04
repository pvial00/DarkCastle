#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void * zander3_ofb_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) { 
    struct qloq_ctx ctx;
    struct qloq_ctx dummy_ctx;
    struct qloq_ctx sign_ctx;
    load_pkfile(keyfile1, &ctx, &dummy_ctx);
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &dummy_ctx, &sign_ctx);
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
    sign(&sign_ctx, S, BNctxt);
    int ctxtbytes = BN_num_bytes(BNctxt);
    unsigned char *password_ctxt[ctxtbytes];
    BN_bn2bin(BNctxt, password_ctxt);
    int Sbytes = BN_num_bytes(S);
    unsigned char *sign_ctxt[Sbytes];
    BN_bn2bin(S, sign_ctxt);

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
    struct zander3_state state;
    uint64_t xl, xr, xp, xq;
    uint8_t output[bufsize];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    xp = ((uint64_t)iv[16] << 56) + ((uint64_t)iv[17] << 48) + ((uint64_t)iv[18] << 40) + ((uint64_t)iv[19] << 32) + ((uint64_t)iv[20] << 24) + ((uint64_t)iv[21] << 16) + ((uint64_t)iv[22] << 8) + (uint64_t)iv[23];
    xq = ((uint64_t)iv[24] << 56) + ((uint64_t)iv[25] << 48) + ((uint64_t)iv[26] << 40) + ((uint64_t)iv[27] << 32) + ((uint64_t)iv[28] << 24) + ((uint64_t)iv[29] << 16) + ((uint64_t)iv[30] << 8) + (uint64_t)iv[31];
    int c = 0;
    int i, b;
    int l = bufsize;
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

    z3gen_subkeys(&state, keyprime, key_length, iv, 32);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, l, infile);
        c = 0;
        int bblocks = bufsize / blocksize;
        int bextra = bufsize % blocksize;
        if (bextra != 0) {
            bblocks += 1;
        }
        if (bufsize < blocksize) {
            bblocks = 1;
        }
        for (b = 0; b < bblocks; b++) {
            z3block_encrypt(&state, &xl, &xr, &xp, &xq);


            output[c] = (xl & 0xFF00000000000000) >> 56;
            output[c+1] = (xl & 0x00FF000000000000) >> 48;
            output[c+2] = (xl & 0x0000FF0000000000) >> 40;
            output[c+3] = (xl & 0x000000FF00000000) >> 32;
            output[c+4] = (xl & 0x00000000FF000000) >> 24;
            output[c+5] = (xl & 0x0000000000FF0000) >> 16;
            output[c+6] = (xl & 0x000000000000FF00) >> 8;
            output[c+7] = (xl & 0x00000000000000FF);
            output[c+8] = (xr & 0xFF00000000000000) >> 56;
            output[c+9] = (xr & 0x00FF000000000000) >> 48;
            output[c+10] = (xr & 0x0000FF0000000000) >> 40;
            output[c+11] = (xr & 0x000000FF00000000) >> 32;
            output[c+12] = (xr & 0x00000000FF000000) >> 24;
            output[c+13] = (xr & 0x0000000000FF0000) >> 16;
            output[c+14] = (xr & 0x000000000000FF00) >> 8;
            output[c+15] = (xr & 0x00000000000000FF);
            output[c+16] = (xp & 0xFF00000000000000) >> 56;
            output[c+17] = (xp & 0x00FF000000000000) >> 48;
            output[c+18] = (xp & 0x0000FF0000000000) >> 40;
            output[c+19] = (xp & 0x000000FF00000000) >> 32;
            output[c+20] = (xp & 0x00000000FF000000) >> 24;
            output[c+21] = (xp & 0x0000000000FF0000) >> 16;
            output[c+22] = (xp & 0x000000000000FF00) >> 8;
            output[c+23] = (xp & 0x00000000000000FF);
            output[c+24] = (xq & 0xFF00000000000000) >> 56;
            output[c+25] = (xq & 0x00FF000000000000) >> 48;
            output[c+26] = (xq & 0x0000FF0000000000) >> 40;
            output[c+27] = (xq & 0x000000FF00000000) >> 32;
            output[c+28] = (xq & 0x00000000FF000000) >> 24;
            output[c+29] = (xq & 0x0000000000FF0000) >> 16;
            output[c+30] = (xq & 0x000000000000FF00) >> 8;
            output[c+31] = (xq & 0x00000000000000FF);
            c += 32;
        }
        for (b = 0; b < bufsize; b++) {
            buffer[b] = buffer[b] ^ output[b];
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * zander3_ofb_decrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int keywrap_ivlen, int mask_bytes, int bufsize, unsigned char * passphrase) { 
    struct qloq_ctx ctx;
    struct qloq_ctx dummy_ctx;
    struct qloq_ctx sign_ctx;
    BIGNUM *tmp;
    BIGNUM *tmpS;
    BIGNUM *BNctxt;
    tmp = BN_new();
    tmpS = BN_new();
    BNctxt = BN_new();
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, &ctx, &dummy_ctx);
    load_pkfile(keyfile2, &dummy_ctx, &sign_ctx);

    int blocksize = 32;
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
    if (verify(&sign_ctx, tmp, tmpS) != 0) {
        printf("Error: Signature verification failed. Message is not authentic.\n");
        exit(2);
    }

    manja_kdf(passkey, password_len, key, key_length, kdf_salt, salt_len, kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);

    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    struct zander3_state state;
    uint64_t xl, xr, xp, xq;
    uint8_t output[bufsize];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    xp = ((uint64_t)iv[16] << 56) + ((uint64_t)iv[17] << 48) + ((uint64_t)iv[18] << 40) + ((uint64_t)iv[19] << 32) + ((uint64_t)iv[20] << 24) + ((uint64_t)iv[21] << 16) + ((uint64_t)iv[22] << 8) + (uint64_t)iv[23];
    xq = ((uint64_t)iv[24] << 56) + ((uint64_t)iv[25] << 48) + ((uint64_t)iv[26] << 40) + ((uint64_t)iv[27] << 32) + ((uint64_t)iv[28] << 24) + ((uint64_t)iv[29] << 16) + ((uint64_t)iv[30] << 8) + (uint64_t)iv[31];
    int c = 0;
    int i;
    int l = 32;
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
    int b;
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length +(mask_bytes*3)), SEEK_SET);
        z3gen_subkeys(&state, keyprime, key_length, iv, 32);
        for (i = 0; i < blocks; i++) {
            if ((i == (blocks - 1)) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / blocksize;
            int bextra = bufsize % blocksize;
            if (bextra != 0) {
                bblocks += 1;
            }
            if (bufsize < blocksize) {
                bblocks = 1;
            }
            for (b = 0; b < bblocks; b++) {
                z3block_encrypt(&state, &xl, &xr, &xp, &xq);


                output[c] = (xl & 0xFF00000000000000) >> 56;
                output[c+1] = (xl & 0x00FF000000000000) >> 48;
                output[c+2] = (xl & 0x0000FF0000000000) >> 40;
                output[c+3] = (xl & 0x000000FF00000000) >> 32;
                output[c+4] = (xl & 0x00000000FF000000) >> 24;
                output[c+5] = (xl & 0x0000000000FF0000) >> 16;
                output[c+6] = (xl & 0x000000000000FF00) >> 8;
                output[c+7] = (xl & 0x00000000000000FF);
                output[c+8] = (xr & 0xFF00000000000000) >> 56;
                output[c+9] = (xr & 0x00FF000000000000) >> 48;
                output[c+10] = (xr & 0x0000FF0000000000) >> 40;
                output[c+11] = (xr & 0x000000FF00000000) >> 32;
                output[c+12] = (xr & 0x00000000FF000000) >> 24;
                output[c+13] = (xr & 0x0000000000FF0000) >> 16;
                output[c+14] = (xr & 0x000000000000FF00) >> 8;
                output[c+15] = (xr & 0x00000000000000FF);
                output[c+16] = (xp & 0xFF00000000000000) >> 56;
                output[c+17] = (xp & 0x00FF000000000000) >> 48;
                output[c+18] = (xp & 0x0000FF0000000000) >> 40;
                output[c+19] = (xp & 0x000000FF00000000) >> 32;
                output[c+20] = (xp & 0x00000000FF000000) >> 24;
                output[c+21] = (xp & 0x0000000000FF0000) >> 16;
                output[c+22] = (xp & 0x000000000000FF00) >> 8;
                output[c+23] = (xp & 0x00000000000000FF);
                output[c+24] = (xq & 0xFF00000000000000) >> 56;
                output[c+25] = (xq & 0x00FF000000000000) >> 48;
                output[c+26] = (xq & 0x0000FF0000000000) >> 40;
                output[c+27] = (xq & 0x000000FF00000000) >> 32;
                output[c+28] = (xq & 0x00000000FF000000) >> 24;
                output[c+29] = (xq & 0x0000000000FF0000) >> 16;
                output[c+30] = (xq & 0x000000000000FF00) >> 8;
                output[c+31] = (xq & 0x00000000000000FF);
                c += 32;
            }
            for (b = 0; b < bufsize; b++) {
                buffer[b] = buffer[b] ^ output[b];
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
