#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int zblocklen = 16;
int z2rounds = 16;

struct zander_state {
    int S[8][256];
    uint64_t K[16];
    uint64_t last[2];
    uint64_t next[2];
    uint64_t r[16];
};

struct zksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t zander_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zander_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *zander_F(struct zksa_state *state) {
    int r;
    for (r = 0; r < 10; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = zander_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = zander_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = zander_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = zander_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = zander_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];

        state->r[15] += state->r[6];
        state->r[2] ^= state->r[15];
        state->r[14] = zander_rotl((state->r[14] ^ state->r[12]), 9);
        state->r[4] += state->r[9];
        state->r[13] ^= state->r[11];
        state->r[6] = zander_rotr((state->r[6] ^ state->r[10]), 6);
        state->r[12] += state->r[13];
        state->r[8] ^= state->r[8];
        state->r[11] = zander_rotl((state->r[11] ^ state->r[3]), 11);
        state->r[10] += state->r[1];
        state->r[1] ^= state->r[4];
        state->r[3] = zander_rotr((state->r[3] ^ state->r[7]), 7);
        state->r[5] += state->r[0];
        state->r[7] ^= state->r[2];
        state->r[9] = zander_rotl((state->r[9] ^ state->r[0]), 3);
        state->r[0] += state->r[5];
    }
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void zgen_subkeys(struct zander_state * state, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int z2rounds) {
    struct zksa_state kstate;
    int c = 0;
    int i;
    memset(state->r, 0, 16*sizeof(uint64_t));
    memset(state->K, 0, 16*sizeof(uint64_t));
    memset(&kstate.r, 0, 16*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));
    memset(state->last, 0, 2*sizeof(uint64_t));
    memset(state->next, 0, 2*sizeof(uint64_t));

    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] = ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    c = 0;
    for (i = 0; i < (ivlen / 8); i++) {
        state->last[i] = 0;
        state->last[i] = ((uint64_t)iv[c] << 56) + ((uint64_t)iv[c+1] << 48) + ((uint64_t)iv[c+2] << 40) + ((uint64_t)iv[c+3] << 32) + ((uint64_t)iv[c+4] << 24) + ((uint64_t)iv[c+5] << 16) + ((uint64_t)iv[c+6] << 8) + (uint64_t)iv[c+7];
	c += 8;
    }
    for (i = 0; i < z2rounds; i++) {
        zander_F(&kstate);
        state->K[i] = 0;
	state->K[i] = kstate.o;
    }
    for (i = 0; i < 16; i++) {
        state->r[i] = state->K[i];
    }
    for (i = 0; i < z2rounds; i++) {
        zander_F(&kstate);
        state->K[i] = 0;
	state->K[i] = kstate.o;
    }

}

void zgen_sbox(struct zander_state * state, unsigned char * key, int keylen) {
    int i, o;
    int s;
    int j = 0;
    int c = 0;
    int temp;
    int k[256];
    for (i = 0; i < 256; i++) {
        k[i] = i;
        k[i] ^= key[c];
        c = (c + 1) % keylen;
        
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            state->S[s][i] = 0;
            state->S[s][i] = i;
        }
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            j = k[j];
            k[j] = (k[c] + k[j]) & 0xff;
            o = (k[k[j]] + k[j]) & 0xff;
            temp = state->S[s][i];
            state->S[s][i] = state->S[s][o];
            state->S[s][o] = temp;
        }
    }
}

uint64_t zF(struct zander_state * state, uint64_t xr) {
    int v, x, y, z, a, b, c, d;
    v = (xr & 0xFF00000000000000) >> 56;
    x = (xr & 0x00FF000000000000) >> 48;
    y = (xr & 0x0000FF0000000000) >> 40;
    z = (xr & 0x000000FF00000000) >> 32;
    a = (xr & 0x00000000FF000000) >> 24;
    b = (xr & 0x0000000000FF0000) >> 16;
    c = (xr & 0x000000000000FF00) >> 8;
    d = (xr & 0x00000000000000FF);

    a = a ^ state->S[4][a];
    b = b ^ state->S[5][b];
    c = c ^ state->S[6][c];
    d = d ^ state->S[7][d];

    a = a ^ state->S[7][d] + state->S[6][a];
    b = b ^ state->S[6][c];
    c = c ^ state->S[5][b];
    d = d ^ state->S[4][a];

    a = a ^ v;
    b = b ^ x;
    c = c ^ y;
    d = d ^ z;
    
    v = v ^ state->S[0][v];
    x = x ^ state->S[1][x];
    y = y ^ state->S[2][y];
    z = z ^ state->S[3][z];

    v = v ^ state->S[1][z] + state->S[2][v];
    x = x ^ state->S[2][y];
    y = y ^ state->S[3][x];
    z = z ^ state->S[0][v];
    xr = ((uint64_t)v << 56) + ((uint64_t)x << 48) + ((uint64_t)y << 40) + ((uint64_t)z << 32) + ((uint64_t)a << 24) + ((uint64_t)b << 16) + ((uint64_t)c << 8) + d;
    return xr;
}

uint64_t zblock_encrypt(struct zander_state * state, uint64_t *xl, uint64_t *xr) {
    int i;
    uint64_t temp;
    uint64_t Xl;
    uint64_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = 0; i < z2rounds; i++) {
        Xr = Xr ^ state->K[i];
        Xl = Xl ^ state->r[i];
        Xl = Xl ^ zF(state, Xr);
        Xl = zander_rotl(Xl, 9);
        Xl += Xr;
        Xr += Xl;

        temp = Xl;
        Xl = Xr;
        Xr = temp;

    }
    temp = Xl;
    Xl = Xr;
    Xr = temp;

    *xl = Xl;
    *xr = Xr;
}

uint64_t zblock_decrypt(struct zander_state * state, uint64_t *xl, uint64_t *xr) {
    int i;
    uint64_t temp;
    uint64_t Xl;
    uint64_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = (z2rounds - 1); i != -1; i--) {
        Xr -= Xl;
        Xl -= Xr;
        Xl = zander_rotr(Xl, 9);
        Xl = Xl ^ zF(state, Xr);
        Xl = Xl ^ state->r[i];
        Xr = Xr ^ state->K[i];

        temp = Xl;
        Xl = Xr;
        Xr = temp;

    }
    temp = Xl;
    Xl = Xr;
    Xr = temp;
    
    *xl = Xl;
    *xr = Xr;
}

void * zander2_cbc_encrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    int blocksize = 16;
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
    uint64_t blocks = datalen / bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    int c = 0;
    int b;
    uint64_t i;
    zgen_subkeys(&state, keyprime, key_length, iv, nonce_length, z2rounds);
    zgen_sbox(&state, keyprime, key_length);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
	if (i == (blocks - 1)) {
            for (int p = 0; p < extrabytes; p++) {
                buffer[(bufsize+extrabytes-1)-p] = (unsigned char *)extrabytes;
	    }
            bufsize = bufsize + extrabytes;
	}
        int bblocks = bufsize / blocksize;
        int bextra = bufsize % blocksize;
        if (bextra != 0) {
            bblocks += 1;
        }
        if (bufsize < blocksize) {
            bblocks = 1;
        }
	for (b = 0; b < bblocks; b++) {
            xl = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
            xr = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
       
	    xl = xl ^ state.last[0];
	    xr = xr ^ state.last[1];

            zblock_encrypt(&state, &xl, &xr);

	    state.last[0] = xl;
	    state.last[1] = xr;
        
            buffer[c] = (xl & 0xFF00000000000000) >> 56;
            buffer[c+1] = (xl & 0x00FF000000000000) >> 48;
            buffer[c+2] = (xl & 0x0000FF0000000000) >> 40;
            buffer[c+3] = (xl & 0x000000FF00000000) >> 32;
            buffer[c+4] = (xl & 0x00000000FF000000) >> 24;
            buffer[c+5] = (xl & 0x0000000000FF0000) >> 16;
            buffer[c+6] = (xl & 0x000000000000FF00) >> 8;
            buffer[c+7] = (xl & 0x00000000000000FF);
            buffer[c+8] = (xr & 0xFF00000000000000) >> 56;
            buffer[c+9] = (xr & 0x00FF000000000000) >> 48;
            buffer[c+10] = (xr & 0x0000FF0000000000) >> 40;
            buffer[c+11] = (xr & 0x000000FF00000000) >> 32;
            buffer[c+12] = (xr & 0x00000000FF000000) >> 24;
            buffer[c+13] = (xr & 0x0000000000FF0000) >> 16;
            buffer[c+14] = (xr & 0x000000000000FF00) >> 8;
            buffer[c+15] = (xr & 0x00000000000000FF);
            c += 16;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    close(infile);
    fclose(outfile);
    manja_kdf(key, key_length, &mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * zander2_cbc_decrypt(char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password,  int keywrap_ivlen, int bufsize) {
    int blocksize = 16;
    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
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
    int count = 0;
    uint64_t xl;
    uint64_t xr;
    uint64_t blocks = datalen / bufsize;
    int extra = datalen % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    int c = 0;
    int b;
    uint64_t i;
    fclose(infile);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        outfile = fopen(outputfile, "wb");
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        zgen_subkeys(&state, keyprime, key_length, iv, nonce_length, z2rounds);
        zgen_sbox(&state, keyprime, key_length);
        for (i = 0; i < blocks; i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            int bblocks = bufsize / blocksize;
            int bextra = bufsize % blocksize;
            if (bextra != 0) {
                bblocks += 1;
            }
            for (b = 0; b < bblocks; b++) {
                xl = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
                xr = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
        
	        state.next[0] = xl;
	        state.next[1] = xr;

                zblock_decrypt(&state, &xl, &xr);
        
	        xl = xl ^ state.last[0];
	        xr = xr ^ state.last[1];
	        state.last[0] = state.next[0];
	        state.last[1] = state.next[1];
        
                buffer[c] = (xl & 0xFF00000000000000) >> 56;
                buffer[c+1] = (xl & 0x00FF000000000000) >> 48;
                buffer[c+2] = (xl & 0x0000FF0000000000) >> 40;
                buffer[c+3] = (xl & 0x000000FF00000000) >> 32;
                buffer[c+4] = (xl & 0x00000000FF000000) >> 24;
                buffer[c+5] = (xl & 0x0000000000FF0000) >> 16;
                buffer[c+6] = (xl & 0x000000000000FF00) >> 8;
                buffer[c+7] = (xl & 0x00000000000000FF);
                buffer[c+8] = (xr & 0xFF00000000000000) >> 56;
                buffer[c+9] = (xr & 0x00FF000000000000) >> 48;
                buffer[c+10] = (xr & 0x0000FF0000000000) >> 40;
                buffer[c+11] = (xr & 0x000000FF00000000) >> 32;
                buffer[c+12] = (xr & 0x00000000FF000000) >> 24;
                buffer[c+13] = (xr & 0x0000000000FF0000) >> 16;
                buffer[c+14] = (xr & 0x000000000000FF00) >> 8;
                buffer[c+15] = (xr & 0x00000000000000FF);
                c += 16;
            }

	    if (i == (blocks - 1)) {
	        int padcheck = buffer[bufsize - 1];
	        int g = bufsize - 1;
	        for (int p = 0; p < padcheck; p++) {
                    if ((int)buffer[g] == padcheck) {
                        count += 1;
		    }
		    g = g - 1;
                }
                if (padcheck == count) {
                    bufsize = bufsize - count;
                }
	    }
            fwrite(buffer, 1, bufsize, outfile);
        }
        fclose(infile);
        fclose(outfile);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

