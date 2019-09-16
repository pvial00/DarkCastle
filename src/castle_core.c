#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ciphers/darkcipher.c"
#include "ciphers/ganja.c"
#include "ciphers/zanderfish2_cbc.c"
#include "ciphers/zanderfish2_ofb.c"
#include "ciphers/zanderfish2_ctr.c"
#include "ciphers/zanderfish3_cbc.c"
#include "ciphers/uvajda.c"
#include "ciphers/spock_cbc.c"
#include "ciphers/specjal_cbc.c"
#include "ciphers/amagus.c"
#include "kdf/manja.c"
#include "hmac/ghmac.c"
#include "crypto_funcs.c"

void dark_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    dark_crypt(msg, keyprime, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void dark_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap256_ivlen);       
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), infile);
        fclose(infile);
        dark_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void uvajda_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    uvajda_crypt(msg, keyprime, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void uvajda_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap256_ivlen);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length-keywrap256_ivlen), infile);
        fclose(infile);
        uvajda_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length-keywrap256_ivlen));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void spockcbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    int extrabytes = 16 - (fsize % 16);
    FILE *infile, *outfile;
    unsigned char *msg;
    int modfsize = (fsize + extrabytes);
    msg = (unsigned char *) malloc(modfsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap128_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap128_ivlen, outfile);
    unsigned char iv[iv_length];
    amagus_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    spock_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, (fsize + extrabytes), outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void spockcbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-keywrap128_ivlen-key_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap128_ivlen];
        fread(kwnonce, 1, keywrap128_ivlen, infile);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - iv_length - keywrap128_ivlen - key_length), infile);
        fclose(infile);
        int pad = spock_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length-keywrap128_ivlen),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap128_ivlen- pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void amagus_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    amagus_crypt(msg, keyprime, key_length, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void amagus_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap256_ivlen);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length-keywrap256_ivlen), infile);
        fclose(infile);
        amagus_crypt(msg, keyprime, key_length,  nonce, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void amagus512_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap512_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap512_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    amagus_crypt(msg, keyprime, key_length, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void amagus512_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap512_ivlen);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap512_ivlen];
        fread(kwnonce, 1, keywrap512_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length-keywrap512_ivlen), infile);
        fclose(infile);
        amagus_crypt(msg, keyprime, key_length,  nonce, (fsize - mac_length - nonce_length - key_length - keywrap512_ivlen));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap512_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void amagus1024_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap1024_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap1024_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    amagus_crypt(msg, keyprime, key_length, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void amagus1024_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap1024_ivlen);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap1024_ivlen];
        fread(kwnonce, 1, keywrap1024_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length-keywrap1024_ivlen), infile);
        fclose(infile);
        amagus_crypt(msg, keyprime, key_length,  nonce, (fsize - mac_length - nonce_length - key_length-keywrap1024_ivlen));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap1024_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void specjalcbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    int extrabytes = 32 - (fsize % 32);
    FILE *infile, *outfile;
    unsigned char *msg;
    int modfsize = (fsize + extrabytes);
    msg = (unsigned char *) malloc(modfsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char iv[iv_length];
    amagus_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    specjal_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, (fsize + extrabytes), outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void specjalcbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length-keywrap256_ivlen);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen), infile);
        fclose(infile);
        int pad = specjal_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void specjalcbc512_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    int extrabytes = 32 - (fsize % 32);
    FILE *infile, *outfile;
    unsigned char *msg;
    int modfsize = (fsize + extrabytes);
    msg = (unsigned char *) malloc(modfsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap512_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap512_ivlen, outfile);
    unsigned char iv[iv_length];
    amagus_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    specjal_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, (fsize + extrabytes), outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void specjalcbc512_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length-keywrap512_ivlen);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap512_ivlen];
        fread(kwnonce, 1, keywrap512_ivlen, infile);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap512_ivlen), infile);
        fclose(infile);
        int pad = specjal_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length - keywrap512_ivlen),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap512_ivlen - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void specjalcbc1024_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    int extrabytes = 32 - (fsize % 32);
    FILE *infile, *outfile;
    unsigned char *msg;
    int modfsize = (fsize + extrabytes);
    msg = (unsigned char *) malloc(modfsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap1024_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap1024_ivlen, outfile);
    unsigned char iv[iv_length];
    amagus_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    specjal_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, (fsize + extrabytes), outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void specjalcbc1024_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length-keywrap1024_ivlen);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap1024_ivlen];
        fread(kwnonce, 1, keywrap1024_ivlen, infile);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap1024_ivlen), infile);
        fclose(infile);
        int pad = specjal_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length - keywrap1024_ivlen),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap1024_ivlen - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zander2cbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    int extrabytes = 16 - (fsize % 16);
    if (extrabytes != 0) {
        fsize += extrabytes;
    }
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char iv[iv_length];
    amagus_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, (fsize-extrabytes), infile);
    zanderfish2_cbc_encrypt(msg, fsize, keyprime, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zander2cbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length-keywrap256_ivlen);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen), infile);
        fclose(infile);
        int pad = zanderfish2_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen),keyprime, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen- pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zander2ofb_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    zanderfish2_ofb_crypt(msg, fsize, keyprime, key_length, nonce, nonce_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zander2ofb_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap256_ivlen);       
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), infile);
        fclose(infile);
        zanderfish2_ofb_crypt(msg, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), keyprime, key_length, nonce, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zander3cbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    int extrabytes = 32 - (fsize % 32);
    if (extrabytes != 0) {
        fsize += extrabytes;
    }
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char iv[iv_length];
    amagus_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, (fsize-extrabytes), infile);
    zanderfish3_cbc_encrypt(msg, fsize, keyprime, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zander3cbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length-keywrap256_ivlen);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen), infile);
        fclose(infile);
        int pad = zanderfish3_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen),keyprime, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - keywrap256_ivlen- pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zander2ctr_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char *kwnonce[keywrap256_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    fwrite(kwnonce, 1, keywrap256_ivlen, outfile);
    unsigned char nonce[nonce_length];
    amagus_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    zanderfish2_ctr_crypt(msg, fsize, keyprime, key_length, nonce, nonce_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zander2ctr_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length-keywrap256_ivlen);       
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        unsigned char *kwnonce[keywrap256_ivlen];
        fread(kwnonce, 1, keywrap256_ivlen, infile);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_decrypt(keyprime, key_length, key, kwnonce);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), infile);
        fclose(infile);
        zanderfish2_ctr_crypt(msg, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), keyprime, key_length, nonce, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length - keywrap256_ivlen), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
