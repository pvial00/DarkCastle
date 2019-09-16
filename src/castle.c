#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "castle_core.c"

void usage() {
    printf("DarkCastle v0.5.4 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\ndark             256 bit\nuvajda           256 bit\nspock-cbc        256 bit\namagus           256 bit\namagus512        512 bit\namagus1024       1024 bit\nspecjal          256 bit\nspecjal512       512 bit\nspecjal1024      1024 bit\nzanderfish2-cbc  256 bit\nzanderfish2-ofb  256 bit\nzanderfish2-ctr  256 bit\nzanderfish3      256 bit\nzanderfish3-512  512 bit\nzanderfish3-1024 1024 bit\n\n");
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

    int zanderfish_key_length = 32;
    int zanderfish2_key_length = 32;
    int zanderfish3_key_length = 32;
    int zanderfish3_512_key_length = 64;
    int zanderfish3_1024_key_length = 128;
    int dark_key_length = 32;
    int uvajda_key_length = 32;
    int spock_key_length = 16;
    int spock256_key_length = 32;
    int amagus_key_length = 32;
    int amagus512_key_length = 64;
    int amagus1024_key_length = 128;
    int specjal_key_length = 32;
    int specjal512_key_length = 64;
    int specjal1024_key_length = 128;

    int dark_mac_length = 32;
    int zanderfish_mac_length = 32;
    int zanderfish2_mac_length = 32;
    int zanderfish3_mac_length = 32;
    int uvajda_mac_length = 32;
    int spock_mac_length = 32;
    int amagus_mac_length = 32;
    int specjal_mac_length = 32;

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
            dark_encrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "uvajda") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            uvajda_encrypt(infile_name, fsize, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            uvajda_decrypt(infile_name, fsize, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "amagus") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(infile_name, fsize, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(infile_name, fsize, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "amagus512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus512_encrypt(infile_name, fsize, outfile_name, amagus512_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus512_decrypt(infile_name, fsize, outfile_name, amagus512_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "amagus1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus1024_encrypt(infile_name, fsize, outfile_name, amagus1024_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus1024_decrypt(infile_name, fsize, outfile_name, amagus1024_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "spock-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spockcbc_encrypt(infile_name, fsize, outfile_name, spock256_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spockcbc_decrypt(infile_name, fsize, outfile_name, spock256_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "specjal") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            specjalcbc_encrypt(infile_name, fsize, outfile_name, specjal_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            specjalcbc_decrypt(infile_name, fsize, outfile_name, specjal_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "specjal512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            specjalcbc512_encrypt(infile_name, fsize, outfile_name, specjal512_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            specjalcbc512_decrypt(infile_name, fsize, outfile_name, specjal512_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "specjal1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            specjalcbc1024_encrypt(infile_name, fsize, outfile_name, specjal1024_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            specjalcbc1024_decrypt(infile_name, fsize, outfile_name, specjal1024_key_length, specjal_nonce_length, specjal_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2cbc_encrypt(infile_name, fsize, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2cbc_decrypt(infile_name, fsize, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2ofb_encrypt(infile_name, fsize, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2ofb_decrypt(infile_name, fsize, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-ctr") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2ctr_encrypt(infile_name, fsize, outfile_name, zanderfish2_key_length, zanderfish2ctr_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2ctr_decrypt(infile_name, fsize, outfile_name, zanderfish2_key_length, zanderfish2ctr_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3cbc_encrypt(infile_name, fsize, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3cbc_decrypt(infile_name, fsize, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish3-512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3cbc_encrypt(infile_name, fsize, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3cbc_decrypt(infile_name, fsize, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish3-1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3cbc_encrypt(infile_name, fsize, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3cbc_decrypt(infile_name, fsize, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    return 0;
}
