#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

/* KryptoMagick L.E.I.A. Cipher [2021] */

/* Lightweight Encryption Iterated Algorithm */

// 256 bit key - 32 rounds

// 512 bit key - 64 rounds

// 1024 bit key - 96 rounds

struct leia_state {
    uint64_t K[32][4];
    uint64_t PRK[4];
    uint64_t POK[4];
    uint64_t last[4];
    uint64_t next[4];
    int rounds;
};

struct leiaksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t leia_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t leia_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *leia_F(struct leiaksa_state *state) {
    int r;
    for (r = 0; r < 16; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = leia_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = leia_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = leia_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = leia_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = leia_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];

        state->r[15] += state->r[6];
        state->r[2] ^= state->r[15];
        state->r[14] = leia_rotl((state->r[14] ^ state->r[12]), 9);
        state->r[4] += state->r[9];
        state->r[13] ^= state->r[11];
        state->r[6] = leia_rotr((state->r[6] ^ state->r[10]), 6);
        state->r[12] += state->r[13];
        state->r[8] ^= state->r[8];
        state->r[11] = leia_rotl((state->r[11] ^ state->r[3]), 11);
        state->r[10] += state->r[1];
        state->r[1] ^= state->r[4];
        state->r[3] = leia_rotr((state->r[3] ^ state->r[7]), 7);
        state->r[5] += state->r[0];
        state->r[7] ^= state->r[2];
        state->r[9] = leia_rotl((state->r[9] ^ state->r[0]), 3);
        state->r[0] += state->r[5];
    }
    state->o = 0;
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void leiagen_subkeys(struct leia_state * state, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    struct leiaksa_state kstate;
    int c = 0;
    int i;
    int s;
    state->rounds = 32;
    memset(state->K, 0, state->rounds*(sizeof(uint64_t)));
    memset(&kstate.r, 0, 16*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));
    memset(state->last, 0, 4*sizeof(uint64_t));
    memset(state->next, 0, 4*sizeof(uint64_t));

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
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            leia_F(&kstate);
            state->K[i][s] = 0;
	    state->K[i][s] = kstate.o;
        }
    }
    for (s = 0; s < 4; s++) {
        leia_F(&kstate);
        state->POK[s] = 0;
        state->POK[s] = kstate.o;
    }
    for (s = 0; s < 4; s++) {
        leia_F(&kstate);
        state->PRK[s] = 0;
        state->PRK[s] = kstate.o;
    }
}

void leia_encrypt(struct leia_state * state, uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
    uint64_t A, B, C, D;

    A = *a;
    B = *b;
    C = *c;
    D = *d;

    A ^= state->PRK[0];
    B ^= state->PRK[1];
    C ^= state->PRK[2]; 
    D ^= state->PRK[3];
    for (int r = 0; r < state->rounds; r++) {
        A += D;
        D += A;
        B = leia_rotl(B, 31);
        D = leia_rotl(D, 21);
        C += B;
        B += C;
        C = leia_rotl(C, 16);
        D = leia_rotl(D, 7);
        B += A;
        A += B;
        D += C;
        C += D;
        A ^= state->K[r][0];
        B ^= state->K[r][1];
        C ^= state->K[r][2];
        D ^= state->K[r][3];
    }
    *a = A ^ state->POK[0];
    *b = B ^ state->POK[1];
    *c = C ^ state->POK[2]; 
    *d = D ^ state->POK[3];

}

void leia_decrypt(struct leia_state * state, uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d) {
    uint64_t A, B, C, D;
    
    A = *a;
    B = *b;
    C = *c;
    D = *d;
    A = A ^ state->POK[0];
    B = B ^ state->POK[1];
    C = C ^ state->POK[2];
    D = D ^ state->POK[3];
    for (int r = (state->rounds - 1); r != -1; r--) {
        D ^= state->K[r][3];
        C ^= state->K[r][2];
        B ^= state->K[r][1];
        A ^= state->K[r][0];
        C -= D;
        D -= C;
        A -= B;
        B -= A;
        D = leia_rotr(D, 7);
        C = leia_rotr(C, 16);
        B -= C;
        C -= B;
        D = leia_rotr(D, 21);
        B = leia_rotr(B, 31);
        D -= A;
        A -= D;

    }
    A ^= state->PRK[0];
    B ^= state->PRK[1];
    C ^= state->PRK[2];
    D ^= state->PRK[3];
    *a = A;
    *b = B;
    *c = C;
    *d = D;
    
}

void * leia_cbc_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
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
    unsigned char S[crypto_sign_BYTES];
    zander3_cbc_decrypt_kf(keyfile2, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);
    load_pkfile(keyfile1, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);
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

    struct leia_state state;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocksize = 32;
    uint64_t blocks = datalen / bufsize;
    int extrabytes = blocksize - (datalen % blocksize);
    int extra = datalen % bufsize;
    int v = blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    if (datalen < bufsize) {
        blocks = 1;
    }
    int c = 0;
    int b;
    uint64_t i;
    leiagen_subkeys(&state, key, key_length, iv, nonce_length);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
	if ((i == (blocks - 1)) && (extra != 0)) {
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
            /*
	    if ((i == (blocks - 1)) && (extra != 0) && (b == (bblocks -1))) {
                for (int p = 0; p < extrabytes; p++) {
                    buffer[(bufsize-1)-p] = (unsigned char *)extrabytes;
	        }
	    } */
	/*    if ((i == (blocks - 1)) && (extra != 0)) {
                for (int p = 0; p < extrabytes; p++) {
                    buffer[(bufsize-1)-p] = (unsigned char *)extrabytes;
	        }
	    } */
	 
            xl = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
            xr = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
            xp = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
            xq = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
       
	    xl = xl ^ state.last[0];
	    xr = xr ^ state.last[1];
	    xp = xp ^ state.last[2];
	    xq = xq ^ state.last[3];

            leia_encrypt(&state, &xl, &xr, &xp, &xq);

	    state.last[0] = xl;
	    state.last[1] = xr;
	    state.last[2] = xp;
	    state.last[3] = xq;
        
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
            buffer[c+16] = (xp & 0xFF00000000000000) >> 56;
            buffer[c+17] = (xp & 0x00FF000000000000) >> 48;
            buffer[c+18] = (xp & 0x0000FF0000000000) >> 40;
            buffer[c+19] = (xp & 0x000000FF00000000) >> 32;
            buffer[c+20] = (xp & 0x00000000FF000000) >> 24;
            buffer[c+21] = (xp & 0x0000000000FF0000) >> 16;
            buffer[c+22] = (xp & 0x000000000000FF00) >> 8;
            buffer[c+23] = (xp & 0x00000000000000FF);
            buffer[c+24] = (xq & 0xFF00000000000000) >> 56;
            buffer[c+25] = (xq & 0x00FF000000000000) >> 48;
            buffer[c+26] = (xq & 0x0000FF0000000000) >> 40;
            buffer[c+27] = (xq & 0x000000FF00000000) >> 32;
            buffer[c+28] = (xq & 0x00000000FF000000) >> 24;
            buffer[c+29] = (xq & 0x0000000000FF0000) >> 16;
            buffer[c+30] = (xq & 0x000000000000FF00) >> 8;
            buffer[c+31] = (xq & 0x00000000000000FF);
            c += 32;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, salt_len, kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * leia_cbc_decrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char Spk[crypto_sign_PUBLICKEYBYTES];
    unsigned char Ssk[crypto_sign_SECRETKEYBYTES];
    unsigned char SpkB[crypto_sign_PUBLICKEYBYTES];
    unsigned char pkB[crypto_box_PUBLICKEYBYTES];
    zander3_cbc_decrypt_kf(keyfile1, 64, 32, 32, kdf_iterations, kdf_salt, 16, 32, passphrase, pk, crypto_box_PUBLICKEYBYTES, sk, crypto_box_SECRETKEYBYTES, Spk, crypto_sign_PUBLICKEYBYTES, Ssk, crypto_sign_SECRETKEYBYTES);
    load_pkfile(keyfile2, pkB, crypto_box_PUBLICKEYBYTES, SpkB, crypto_sign_PUBLICKEYBYTES);

    FILE *infile, *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *passtmp[(crypto_box_SEALBYTES + key_length)];
    unsigned char S[crypto_sign_BYTES];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    int extrabytes = 32 - (datalen % 32);
    fseek(infile, 0, SEEK_SET);

    fread(&mac, 1, mac_length, infile);
    fread(S, 1, crypto_sign_BYTES, infile);
    fread(passtmp, 1, crypto_box_SEALBYTES + key_length, infile);
    fread(iv, 1, nonce_length, infile);
    datalen = datalen - key_length - mac_length - nonce_length - crypto_box_SEALBYTES - crypto_sign_BYTES;
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

    struct leia_state state;
    int count = 0;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocksize = 32;
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
        fseek(infile, (mac_length + nonce_length + key_length +  crypto_box_SEALBYTES + crypto_sign_BYTES), SEEK_SET);
        leiagen_subkeys(&state, key, key_length, iv, nonce_length);
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
                xp = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
                xq = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
        
	        state.next[0] = xl;
	        state.next[1] = xr;
	        state.next[2] = xp;
	        state.next[3] = xq;

                leia_decrypt(&state, &xl, &xr, &xp, &xq);
        
	        xl = xl ^ state.last[0];
	        xr = xr ^ state.last[1];
	        xp = xp ^ state.last[2];
	        xq = xq ^ state.last[3];
	        state.last[0] = state.next[0];
	        state.last[1] = state.next[1];
	        state.last[2] = state.next[2];
	        state.last[3] = state.next[3];
        
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
                buffer[c+16] = (xp & 0xFF00000000000000) >> 56;
                buffer[c+17] = (xp & 0x00FF000000000000) >> 48;
                buffer[c+18] = (xp & 0x0000FF0000000000) >> 40;
                buffer[c+19] = (xp & 0x000000FF00000000) >> 32;
                buffer[c+20] = (xp & 0x00000000FF000000) >> 24;
                buffer[c+21] = (xp & 0x0000000000FF0000) >> 16;
                buffer[c+22] = (xp & 0x000000000000FF00) >> 8;
                buffer[c+23] = (xp & 0x00000000000000FF);
                buffer[c+24] = (xq & 0xFF00000000000000) >> 56;
                buffer[c+25] = (xq & 0x00FF000000000000) >> 48;
                buffer[c+26] = (xq & 0x0000FF0000000000) >> 40;
                buffer[c+27] = (xq & 0x000000FF00000000) >> 32;
                buffer[c+28] = (xq & 0x00000000FF000000) >> 24;
                buffer[c+29] = (xq & 0x0000000000FF0000) >> 16;
                buffer[c+30] = (xq & 0x000000000000FF00) >> 8;
                buffer[c+31] = (xq & 0x00000000000000FF);
                c += 32;
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
