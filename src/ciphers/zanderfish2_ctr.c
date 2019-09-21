#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void * zander2_ctr_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
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
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(iv, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    struct zander_state state;
    uint64_t xl;
    uint64_t xr;
    uint8_t output[16];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    //xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    xr = 0;
    uint64_t blocks = datalen / zblocklen;
    uint64_t i;
    int extra = datalen % zblocklen;
    int c = 0;
    int b;
    int l = 16;
    if (extra != 0) {
        blocks +=1;
    }
    zgen_subkeys(&state, keyprime, key_length, iv, nonce_length, z2rounds);
    zgen_sbox(&state, keyprime, key_length);
    for (i = 0; i < blocks; i++) {
	if ((i == (blocks - 1)) && (extra != 0)) {
            l = extra;
	}

        zblock_encrypt(&state, &xl, &xr);
        xr += 1;


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
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * zander2_ctr_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    bufsize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen;
    fseek(infile, 0, SEEK_SET);
    fread(&mac, 1, mac_length, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);
    struct zander_state state;
    uint64_t xl;
    uint64_t xr;
    uint8_t output[16];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    //xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    xr = 0;
    uint64_t blocks = datalen / zblocklen;
    uint64_t i;
    int extra = datalen % zblocklen;
    int c = 0;
    int b;
    int l = 16;
    if (extra != 0) {
        blocks +=1;
    }
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        zgen_subkeys(&state, keyprime, key_length, iv, nonce_length, z2rounds);
        zgen_sbox(&state, keyprime, key_length);
        for (i = 0; i < blocks; i++) {
	    if (i == (blocks - 1) && (extra != 0)) {
                l = extra;
	    }

            zblock_encrypt(&state, &xl, &xr);
            xr += 1;


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
