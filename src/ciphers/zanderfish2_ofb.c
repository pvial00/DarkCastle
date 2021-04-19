#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void * zander2_ofb_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
    load_pkfile(keyfile1, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);

    bufsize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    amagus_random(&iv, nonce_length);
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
    fwrite(iv, 1, nonce_length, outfile);
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
    zgen_subkeys(&state, key, key_length, iv, nonce_length, z2rounds);
    zgen_sbox(&state, key, key_length);
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

void * zander2_ofb_decrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);
    load_pkfile(keyfile2, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);

    bufsize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
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
    fread(iv, 1, nonce_length, infile);
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
        fseek(infile, (mac_length + nonce_length + key_length + crypto_box_SEALBYTES + crypto_sign_BYTES), SEEK_SET);
        zgen_subkeys(&state, key, key_length, iv, nonce_length, z2rounds);
        zgen_sbox(&state, key, key_length);
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
