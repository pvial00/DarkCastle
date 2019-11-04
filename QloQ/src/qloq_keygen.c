#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qloq.h"

int main(int argc, char *argv[]) {
    int psize = 1536;
    if (argc < 2) {
        psize = 1536;
    }
    else {
        psize = atoi(argv[1]);
    }
    struct qloq_ctx ctx;
    keygen(&ctx, psize);
    return 0;
}

