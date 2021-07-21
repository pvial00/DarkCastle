#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "ciphers/uvajda_oneshot.c"
#include "ciphers/amagus_oneshot.c"
#include "crypto_funcs.c"
#include "kdf/manja.c"
#include "ciphers/ganja.c"
#include "hmac/ghmac.c"
#include "ciphers/zanderfish3_cbc.c"
#include "keygen/keygen.c"
#include "ciphers/albion_cbc.c"
#include "ciphers/uvajda.c"
#include "ciphers/darkcipher.c"
#include "ciphers/zanderfish2_cbc.c"
#include "ciphers/zanderfish2_ofb.c"
#include "ciphers/zanderfish3_ofb.c"
#include "ciphers/spock_cbc.c"
#include "ciphers/qapla.c"
#include "ciphers/akms_cbc.c"
#include "ciphers/darkdragon.c"
#include "ciphers/leia_cbc.c"
#include "ciphers/herne_cbc.c"

void usage() {
    printf("DarkCastle v1.3.8 - by KryptoMagick\n\n");
    printf("Algorithms:\n***********\nalbion           256 bit\nakms             256 bit\nherne            256 bit\ndark             256 bit\ndarkdragon       256 bit\nuvajda           256 bit\nspock            256 bit\nqapla            256 bit\nleia-cbc         256 bit\nzanderfish2-cbc  256 bit\nzanderfish2-ofb  256 bit\nzanderfish3      256 bit\nzanderfish3-512  512 bit\nzanderfish3-1024 1024 bit\nzanderfish3-ofb  256 bit\n");
    printf("Usage:\ncastle <algorithm> -e <input file> <output file> <public keyfile> <secret keyfile>\n");
    printf("castle <algorithm> -d <input file> <output file> <secret keyfile> <public keyfile>\n\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "KryptoMagikDCv10";
    int salt_len = 16;
    int kdf_iterations = 100000;
    int password_len = 256;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int albion_nonce_length = 32;
    int akms_nonce_length = 16;
    int zanderfish2_nonce_length = 16;
    int zanderfish3_nonce_length = 32;
    int dark_nonce_length = 16;
    int uvajda_nonce_length = 16;
    int spock_nonce_length = 16;
    int qapla_nonce_length = 16;
    int leia_nonce_length = 32;

    int albion_key_length = 32;
    int akms_key_length = 32;
    int zanderfish_key_length = 32;
    int zanderfish2_key_length = 32;
    int zanderfish3_key_length = 32;
    int zanderfish3_512_key_length = 64;
    int zanderfish3_1024_key_length = 128;
    int dark_key_length = 32;
    int uvajda_key_length = 32;
    int spock_key_length = 32;
    int qapla_key_length = 32;
    int leia_key_length = 32;

    int albion_mac_length = 32;
    int akms_mac_length = 32;
    int dark_mac_length = 32;
    int zanderfish_mac_length = 32;
    int zanderfish2_mac_length = 32;
    int zanderfish3_mac_length = 32;
    int leia_mac_length = 32;
    int uvajda_mac_length = 32;
    int spock_mac_length = 32;
    int qapla_mac_length = 32;
    int beleth_mac_length = 32;
    int beleth_iv_length = 32;

    int albion_bufsize = 131072;
    int akms_bufsize = 131072;
    int dark_bufsize = 32768;
    int uvajda_bufsize = 32768;
    int zanderfish2_cbc_bufsize = 131072;
    int zanderfish3_bufsize = 262144;
    int leia_bufsize = 262144;
    int zanderfish2_ofb_bufsize = 262144;
    int spock_bufsize = 262144;
    int qapla_bufsize = 262144;

    if (sodium_init() == -1) {
        printf("Error: Libsodium is not functioning\n");
        return 1;
    }

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
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);

    unsigned char * passphrase[256];
    printf("Enter secret key passphrase: ");
    scanf("%s", passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &save);

    if (strcmp(algorithm, "dark") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, dark_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, dark_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "uvajda") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            uvajda_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, uvajda_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            uvajda_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, uvajda_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "spock") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spock_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, spock_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spock_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, spock_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish2_cbc_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish2_cbc_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish2_ofb_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish2_ofb_bufsize, passphrase);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-512") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_512_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
    } 
    else if (strcmp(algorithm, "zanderfish3-1024") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_1024_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, zanderfish3_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "qapla") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            qapla_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, qapla_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            qapla_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, qapla_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "akms") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            akms_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, akms_key_length, akms_nonce_length, akms_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, akms_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            akms_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, akms_key_length, akms_nonce_length, akms_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, akms_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "darkdragon") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            darkdragon_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, dark_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            darkdragon_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, dark_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "leia-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            leia_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, leia_key_length, leia_nonce_length, leia_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, leia_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            leia_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, leia_key_length, leia_nonce_length, leia_mac_length, kdf_iterations, kdf_salt, salt_len, password_len, leia_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "albion") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            albion_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, albion_key_length, albion_nonce_length, beleth_mac_length, beleth_iv_length, kdf_iterations, kdf_salt, salt_len, password_len, albion_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            albion_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, albion_key_length, albion_nonce_length, beleth_mac_length, beleth_iv_length, kdf_iterations, kdf_salt, salt_len, password_len, albion_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "herne") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            herne_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, albion_key_length, albion_nonce_length, beleth_mac_length, beleth_iv_length, kdf_iterations, kdf_salt, salt_len, password_len, albion_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            herne_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, albion_key_length, albion_nonce_length, beleth_mac_length, beleth_iv_length, kdf_iterations, kdf_salt, salt_len, password_len, albion_bufsize, passphrase);
        }
    }
    printf("\n");
    return 0;
}
