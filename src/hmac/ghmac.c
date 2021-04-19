#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void * ganja_hmac(char *inputfile, char *tmpprefix, unsigned char * key, int keylen) {
    int rounds = 8 * 8;
    int bufsize = 131072;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char mac[32] = {0};
    uint32_t H[8] = {0};
    uint32_t temp32[8] = {0};
    uint32_t t, m;
    uint32_t W[8];
    W[0] = 0x72000000;
    W[1] = 0xacdef012;
    W[2] = 0x0059c491;
    W[3] = 0xb8a79b02;
    W[4] = 0x31ba94b9;
    W[5] = 0x45000057;
    W[6] = 0xb5f3810a;
    W[7] = 0x8a348b7d;
    FILE *infile, *outfile;
    int b, f, s, r;
    uint64_t i, blocks;
    int c = 0;
    s = 0;
    m = 0x00000001;

    uint64_t datalen;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    blocks = datalen / bufsize;
    int bs = bufsize;
    int blocks_extra = datalen % bufsize;
    if (blocks_extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
        bufsize = datalen;
        blocks_extra = datalen;
    }

    for (i = 0; i < (keylen / 4); i++) {
        W[i & 0x07] ^= (key[s] << 24) + (key[s+1] << 16) + (key[s+2] << 8) + key[s+3];
        H[i & 0x07] ^= (key[s] << 24) + (key[s+1] << 16) + (key[s+2] << 8) + key[s+3];
        W[i & 0x07] = (W[i & 0x07] + m + H[i & 0x07]) & 0xFFFFFFFF;
        s += 4;
    }
        
    s = 0;
    for (i = 0; i < blocks; i++) {
        fread(&buffer, 1, bufsize, infile);
        if ((i == (blocks -1)) && (blocks_extra != 0)) {
            bufsize = blocks_extra;
        }
        for (r = 0; r < bufsize; r++) {
            H[s] ^= buffer[r];
            H[s] = ((H[s] + m + buffer[r]) & 0xFFFFFFFF) ^ W[s];
            s = (s + 1) & 0x07;
        }
    }
    int l = 4;
    for (r = 0; r < rounds; r++) {
       memcpy(temp32, H, 8 * sizeof(uint32_t));
       H[0] = (H[0] + H[1]) & 0xFFFFFFFF;
       H[1] = rotl(H[1] ^ H[2], 2);
       H[2] = (H[2] + H[3]) & 0xFFFFFFFF;
       H[3] = rotl(H[3] ^ H[4], 5);
       H[4] = (H[4] + H[5]) & 0xFFFFFFFF;
       H[5] = rotl(H[5] ^ H[6], 7);
       H[6] = (H[6] + H[7]) & 0xFFFFFFFF;
       H[7] = rotl(H[7] ^ H[0], 12);
       for (s = 0; s < 7; s++) {
           t = H[s];
	   H[s] = H[(s + 1) & 0x07];
	   H[(s + 1) & 0x07] = t;
        }
        for (s = 0; s < 8; s++) {
            H[s] = (temp32[s] + H[s]) & 0xFFFFFFFF;
        }
    }

    for (s = 0; s < 8; s++) {
        H[s] ^= W[s];
    }

	    
    c = 0;
    for (i = 0; i < 8; i++) {
        mac[c] = (H[i] & 0xFF000000) >> 24;
        mac[c+1] = (H[i] & 0x00FF0000) >> 16;
        mac[c+2] = (H[i] & 0x0000FF00) >> 8;
        mac[c+3] = (H[i] & 0x000000FF);
	c = (c + 4);
    }
    char machex[32*2+1];
    for (i = 0; i < 32; i++) {
        sprintf(&machex[i*2], "%02x", mac[i]);
    }
    unsigned char tmpbytes[4];
    amagus_random(&tmpbytes, 4);
    char tmphex[4*2+1];
    for (i = 0; i < 4; i++) {
        sprintf(&tmphex[i*2], "%02x", tmpbytes[i]);
    }
    char tempfilename[16];
    strcpy(&tempfilename, tmpprefix);
    strcat(&tempfilename, &tmphex);
    fclose(infile);
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(tempfilename, "wb");
    fwrite(mac, 1, 32, outfile);
    blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
        extra = 0;
        bufsize = datalen;
    }
    for (i = 0; i < blocks; i++)  {
       if ((i == (blocks -1)) && (extra != 0)) {
           bufsize = extra;
       }
       fread(buffer, 1, bufsize, infile);
       fwrite(buffer, 1, bufsize, outfile);
   }
   fclose(infile);
   fclose(outfile);
   char cmdprefix[4] = "mv ";
   char cmd[320];
   strcpy(&cmd, cmdprefix);
   strcat(&cmd, tempfilename);
   strcat(&cmd, " ");
   strcat(&cmd, inputfile);
   system(cmd);
}

int * ganja_hmac_verify(char *inputfile, unsigned char * key, int keylen) {
    int rounds = 8 * 8;
    int bufsize = 131072;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char mac[32] = {0};
    unsigned char mac_verify[32] = {0};
    uint32_t H[8] = {0};
    uint32_t temp32[8] = {0};
    uint32_t t, m;
    uint32_t W[8];
    W[0] = 0x72000000;
    W[1] = 0xacdef012;
    W[2] = 0x0059c491;
    W[3] = 0xb8a79b02;
    W[4] = 0x31ba94b9;
    W[5] = 0x45000057;
    W[6] = 0xb5f3810a;
    W[7] = 0x8a348b7d;
    unsigned char buf;
    FILE *infile, *outfile;
    int b, f, s, r, blocks;
    unsigned long long i;
    int c = 0;
    m = 0x00000001;

    unsigned long long datalen;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = (ftell(infile) - 32);
    fseek(infile, 0, SEEK_SET);
    fread(&mac_verify, 1, 32, infile);
    blocks = datalen / bufsize;
    int blocks_extra = datalen % bufsize;
    if (blocks_extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
        blocks_extra = datalen;
        bufsize = datalen;
    }
    char macvhex[32*2+1];
    for (i = 0; i < 32; i++) {
        sprintf(&macvhex[i*2], "%02x", mac_verify[i]);
    }
    s = 0;
    for (i = 0; i < (keylen / 4); i++) {
        W[i & 0x07] ^= (key[s] << 24) + (key[s+1] << 16) + (key[s+2] << 8) + key[s+3];
        H[i & 0x07] ^= (key[s] << 24) + (key[s+1] << 16) + (key[s+2] << 8) + key[s+3];
        W[i & 0x07] = (W[i & 0x07] + m + H[i & 0x07]) & 0xFFFFFFFF;
        s += 4;
    }
        
    s = 0;
    for (i = 0; i < blocks; i++) {
        fread(&buffer, 1, bufsize, infile);
        if ((i == (blocks -1)) && (datalen > bufsize)) {
            bufsize = blocks_extra;
        }
        for (r = 0; r < bufsize; r++) {
            H[s] ^= buffer[r];
            H[s] = ((H[s] + m + buffer[r]) & 0xFFFFFFFF) ^ W[s];
            s = (s + 1) & 0x07;
        }
    }
    fclose(infile);
    int l = 4;
    for (r = 0; r < rounds; r++) {
       memcpy(temp32, H, 8 * sizeof(uint32_t));
       H[0] = (H[0] + H[1]) & 0xFFFFFFFF;
       H[1] = rotl(H[1] ^ H[2], 2);
       H[2] = (H[2] + H[3]) & 0xFFFFFFFF;
       H[3] = rotl(H[3] ^ H[4], 5);
       H[4] = (H[4] + H[5]) & 0xFFFFFFFF;
       H[5] = rotl(H[5] ^ H[6], 7);
       H[6] = (H[6] + H[7]) & 0xFFFFFFFF;
       H[7] = rotl(H[7] ^ H[0], 12);
       for (s = 0; s < 7; s++) {
           t = H[s];
	   H[s] = H[(s + 1) & 0x07];
	   H[(s + 1) & 0x07] = t;
        }
        for (s = 0; s < 8; s++) {
            H[s] = (temp32[s] + H[s]) & 0xFFFFFFFF;
        }
    }

    for (s = 0; s < 8; s++) {
        H[s] ^= W[s];
    }

	    
    c = 0;
    for (i = 0; i < 8; i++) {
        mac[c] = (H[i] & 0xFF000000) >> 24;
        mac[c+1] = (H[i] & 0x00FF0000) >> 16;
        mac[c+2] = (H[i] & 0x0000FF00) >> 8;
        mac[c+3] = (H[i] & 0x000000FF);
	c = (c + 4);
    }
    char machex[32*2+1];
    for (i = 0; i < 32; i++) {
        sprintf(&machex[i*2], "%02x", mac[i]);
    }
    if (memcmp(mac, mac_verify, 32) == 0) {
        return 0;
    }
    else {
        return 1;
    }
}
