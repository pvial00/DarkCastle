#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ciphers/qloq.h"
#include "ciphers/uvajda_oneshot.c"
#include "ciphers/amagus_oneshot.c"
#include "crypto_funcs.c"
#include "kdf/manja.c"
#include "ciphers/ganja.c"
#include "hmac/ghmac.c"
#include "ciphers/uvajda.c"
#include "ciphers/amagus.c"
#include "ciphers/darkcipher.c"
#include "ciphers/zanderfish2_cbc.c"
#include "ciphers/zanderfish2_ofb.c"
#include "ciphers/zanderfish2_ctr.c"
#include "ciphers/zanderfish3_cbc.c"
#include "ciphers/zanderfish3_ofb.c"
#include "ciphers/spock_cbc.c"
#include "ciphers/qapla.c"

void usage() {
    printf("DarkCastle v0.8 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\ndark             256 bit\nuvajda           256 bit\nspock            256 bit\namagus           256 bit\namagus512        512 bit\namagus1024       1024 bit\nqapla            256 bit\nzanderfish2-cbc  256 bit\nzanderfish2-ofb  256 bit\nzanderfish2-ctr  256 bit\nzanderfish3      256 bit\nzanderfish3-512  512 bit\nzanderfish3-1024 1024 bit\nzanderfish3-ofb  256 bit\n\n");
    printf("Usage:\ncastle <algorithm> -e <input file> <output file> <public keyfile> <secret keyfile>\n");
    printf("castle <algorithm> -d <input file> <output file> <secret keyfile> <public keyfile>\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "KryptoMagikDCv07";
    int salt_len = 16;
    int kdf_iterations = 10000;
    int password_len = 256;
    int mask_bytes = 384;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish2_nonce_length = 16;
    int zanderfish2ctr_nonce_length = 8;
    int zanderfish3_nonce_length = 32;
    int dark_nonce_length = 16;
    int uvajda_nonce_length = 16;
    int spock_nonce_length = 16;
    int amagus_nonce_length = 16;
    int qapla_nonce_length = 16;

    int zanderfish_key_length = 32;
    int zanderfish2_key_length = 32;
    int zanderfish3_key_length = 32;
    int zanderfish3_512_key_length = 64;
    int zanderfish3_1024_key_length = 128;
    int dark_key_length = 32;
    int uvajda_key_length = 32;
    int spock_key_length = 32;
    int amagus_key_length = 32;
    int amagus512_key_length = 64;
    int amagus1024_key_length = 128;
    int qapla_key_length = 32;

    int dark_mac_length = 32;
    int zanderfish_mac_length = 32;
    int zanderfish2_mac_length = 32;
    int zanderfish3_mac_length = 32;
    int uvajda_mac_length = 32;
    int spock_mac_length = 32;
    int amagus_mac_length = 32;
    int qapla_mac_length = 32;

    int dark_bufsize = 32768;
    int uvajda_bufsize = 32768;
    int amagus_bufsize = 655536;
    int zanderfish2_cbc_bufsize = 131072;
    int zanderfish3_bufsize = 262144;
    int zanderfish2_ofb_bufsize = 262144;
    int zanderfish2_ctr_bufsize = 262144;
    int spock_bufsize = 131072;
    int qapla_bufsize = 262144;

    if (argc != 7) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *keyfile1_name, *keyfile2_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    keyfile1_name = argv[5];
    keyfile2_name = argv[6];
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);

    if (strcmp(algorithm, "dark") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, dark_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, dark_bufsize);
        }
    }
    else if (strcmp(algorithm, "uvajda") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            uvajda_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, uvajda_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            uvajda_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, uvajda_bufsize);
        }
    }
    else if (strcmp(algorithm, "amagus") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, amagus_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, amagus_bufsize);
        }
    }
    else if (strcmp(algorithm, "amagus512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, amagus512_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap512_ivlen, mask_bytes, amagus_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, amagus512_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap512_ivlen, mask_bytes, amagus_bufsize);
        }
    }
    else if (strcmp(algorithm, "amagus1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, amagus1024_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap1024_ivlen, mask_bytes, amagus_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, amagus1024_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap1024_ivlen, mask_bytes, amagus_bufsize);
        }
    }
    else if (strcmp(algorithm, "spock") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spock_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spock_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spock_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, spock_bufsize);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_cbc_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_cbc_bufsize);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_ofb_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_ofb_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish2-ctr") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_ctr_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2ctr_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_ctr_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_ctr_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2ctr_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_ctr_bufsize);
        }
    }
    else if (strcmp(algorithm, "zanderfish3-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize);
        }
    }
    else if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap512_ivlen, mask_bytes, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap512_ivlen, mask_bytes, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap1024_ivlen, mask_bytes, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap1024_ivlen, mask_bytes, zanderfish3_bufsize);
        }
    }
    else if (strcmp(algorithm, "qapla") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            qapla_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, qapla_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            qapla_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, keywrap256_ivlen, mask_bytes, qapla_bufsize);
        }
    }
    return 0;
}
