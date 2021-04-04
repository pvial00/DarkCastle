#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void qloq_keygen(int psize, char * prefix, unsigned char * passphrase, unsigned char * kdf_salt, int kdf_iterations) {
    struct qloq_ctx ctx;
    struct qloq_ctx sign_ctx;
    keygen(&ctx, psize, prefix);
    keygen(&sign_ctx, psize, prefix);

    char *skfilename[256];
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");

    int total = pkg_sk_bytes_count(&ctx, &sign_ctx);
    unsigned char * keyblob = (unsigned char *) malloc(total);
    pkg_pk(&ctx, &sign_ctx, prefix);
    pkg_sk_bytes(&ctx, &sign_ctx, keyblob);
    zander3_cbc_encrypt_kf(keyblob, total, skfilename, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase);
    free(keyblob);
}
