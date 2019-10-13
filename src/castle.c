#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "ciphers/specjal_cbc.c"
#include "ciphers/zywca_cbc.c"
#include "ciphers/qapla.c"

void usage() {
    printf("DarkCastle v0.6.6.6 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\ndark             256 bit\nuvajda           256 bit\nspock            256 bit\namagus           256 bit\namagus512        512 bit\namagus1024       1024 bit\nqapla            256 bit\nspecjal          256 bit\nspecjal512       512 bit\nzanderfish2-cbc  256 bit\nzanderfish2-ofb  256 bit\nzanderfish2-ctr  256 bit\nzanderfish3      256 bit\nzanderfish3-512  512 bit\nzanderfish3-1024 1024 bit\nzanderfish3-ofb  256 bit\nzywca            256 bit\n");
    printf("Usage: castle <algorithm> <-e/-d> <input file> <output file> <password>\n\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "CastleCipherSui";
    int kdf_iterations = 10000;
    int max_password_len = 256;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish2_nonce_length = 16;
    int zanderfish2ctr_nonce_length = 8;
    int zanderfish3_nonce_length = 32;
    int dark_nonce_length = 16;
    int uvajda_nonce_length = 16;
    int spock_nonce_length = 16;
    int amagus_nonce_length = 16;
    int specjal_nonce_length = 32;
    int zywca_nonce_length = 32;
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
    int specjal_key_length = 32;
    int specjal512_key_length = 64;
    int zywca_key_length = 32;
    int qapla_key_length = 32;

    int dark_mac_length = 32;
    int zanderfish_mac_length = 32;
    int zanderfish2_mac_length = 32;
    int zanderfish3_mac_length = 32;
    int uvajda_mac_length = 32;
    int spock_mac_length = 32;
    int amagus_mac_length = 32;
    int specjal_mac_length = 32;
    int zywca_mac_length = 32;
    int qapla_mac_length = 32;

    int dark_bufsize = 32768;
    int uvajda_bufsize = 32768;
    int amagus_bufsize = 655536;
    int zanderfish2_cbc_bufsize = 131072;
    int zanderfish3_bufsize = 262144;
    int zanderfish2_ofb_bufsize = 262144;
    int zanderfish2_ctr_bufsize = 262144;
    int spock_bufsize = 131072;
    int specjal_bufsize = 131072;
    int zywca_bufsize = 262144;
    int qapla_bufsize = 262144;
    

    if (argc != 6) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    unsigned char *password = argv[5];
    if (strlen(password) > max_password_len) {
        printf("Max password limit %d bytes has been exceeded.\n", max_password_len);
        exit(1);
    }
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
            dark_encrypt(infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, dark_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, dark_bufsize);
        }
    }
    else if (strcmp(algorithm, "uvajda") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            uvajda_encrypt(infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, uvajda_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            uvajda_decrypt(infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, uvajda_bufsize);
        }
    }
    else if (strcmp(algorithm, "amagus") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(infile_name, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, amagus_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(infile_name, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, amagus_bufsize);
        }
    }
    else if (strcmp(algorithm, "amagus512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(infile_name, outfile_name, amagus512_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, amagus_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(infile_name, outfile_name, amagus512_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, amagus_bufsize);
        }
    }
    else if (strcmp(algorithm, "amagus1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(infile_name, outfile_name, amagus1024_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password, keywrap1024_ivlen, amagus_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(infile_name, outfile_name, amagus1024_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password, keywrap1024_ivlen, amagus_bufsize);
        }
    }
    else if (strcmp(algorithm, "spock") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spock_cbc_encrypt(infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, spock_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spock_cbc_decrypt(infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, spock_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish2-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_cbc_encrypt(infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish2_cbc_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_cbc_decrypt(infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish2_cbc_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish2-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_ofb_encrypt(infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish2_ofb_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_ofb_decrypt(infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish2_ofb_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish2-ctr") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_ctr_encrypt(infile_name, outfile_name, zanderfish2_key_length, zanderfish2ctr_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish2_ctr_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_ctr_decrypt(infile_name, outfile_name, zanderfish2_key_length, zanderfish2ctr_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish2_ctr_bufsize);
        }
    }
    else if (strcmp(algorithm, "zanderfish3-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_ofb_encrypt(infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_ofb_decrypt(infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap1024_ivlen, zanderfish3_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password, keywrap1024_ivlen, zanderfish3_bufsize);
        }
    } 
    else if (strcmp(algorithm, "specjal") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            specjal_cbc_encrypt(infile_name, outfile_name, specjal_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, specjal_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            specjal_cbc_decrypt(infile_name, outfile_name, specjal_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, specjal_bufsize);
        }
    } 
    else if (strcmp(algorithm, "specjal512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            specjal_cbc_encrypt(infile_name, outfile_name, specjal512_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, specjal_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            specjal_cbc_decrypt(infile_name, outfile_name, specjal512_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password, keywrap512_ivlen, specjal_bufsize);
        }
    } 
    else if (strcmp(algorithm, "zywca") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zywca_cbc_encrypt(infile_name, outfile_name, zywca_key_length, zywca_nonce_length, zywca_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zywca_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zywca_cbc_decrypt(infile_name, outfile_name, zywca_key_length, zywca_nonce_length, zywca_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, zywca_bufsize);
        }
    } 
    else if (strcmp(algorithm, "qapla") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            qapla_encrypt(infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, qapla_bufsize);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            qapla_decrypt(infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, password, keywrap256_ivlen, qapla_bufsize);
        }
    }
    return 0;
}
