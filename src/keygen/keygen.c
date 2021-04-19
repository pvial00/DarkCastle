#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

void pkg_libsodium_pk(unsigned char * pk, unsigned * Spk, char * prefix) {
    FILE *tmpfile;
    char *pkfilename[256];
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".pk");
    tmpfile = fopen(pkfilename, "wb");
    fwrite(pk, 1, crypto_box_PUBLICKEYBYTES, tmpfile);
    fwrite(Spk, 1, crypto_sign_PUBLICKEYBYTES, tmpfile);

    fclose(tmpfile);
}

void pkg_libsodium_sk(unsigned char * sk, unsigned char * Ssk, char * prefix) {
    FILE *tmpfile;
    char *skfilename[256];
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    tmpfile = fopen(skfilename, "wb");
    fwrite(sk, 1, crypto_box_SECRETKEYBYTES, tmpfile);
    fwrite(Ssk, 1, crypto_sign_SECRETKEYBYTES, tmpfile);
    fclose(tmpfile);
}

void darkcastle_keygen(char * prefix, unsigned char * passphrase, unsigned char * kdf_salt, int kdf_iterations) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char keyblob[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
    crypto_sign_keypair(Spk, Ssk);
    char *skfilename[256];
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    int pos = 0;
    for (int i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
        keyblob[pos] = pk[i];
        pos += 1;
    }
    for (int i = 0; i < crypto_box_SECRETKEYBYTES; i++) {
        keyblob[pos] = sk[i];
        pos += 1;
    }
    for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++) {
        keyblob[pos] = Spk[i];
        pos += 1;
    }
    for (int i = 0; i < crypto_sign_SECRETKEYBYTES; i++) {
        keyblob[pos] = Ssk[i];
        pos += 1;
    }


    pkg_libsodium_pk(pk, Spk, prefix);
    zander3_cbc_encrypt_kf(keyblob, crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES, skfilename, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase);
}
