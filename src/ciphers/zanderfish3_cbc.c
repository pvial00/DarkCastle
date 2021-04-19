#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

int z3blocklen = 32;

int t0 = 0x57bf953b78f054bc;
int t1 = 0x0a78a94e98868e69;

struct zander3_state {
    uint64_t K[80][4];
    uint64_t K2[80][4];
    uint64_t K3[80][4];
    uint64_t K4[80][2];
    uint64_t D[4];
    uint64_t last[4];
    uint64_t next[4];
    int rounds;
};

struct z3ksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t zander3_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zander3_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *zander3_F(struct z3ksa_state *state) {
    int r;
    for (r = 0; r < 16; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = zander3_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = zander3_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = zander3_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = zander3_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = zander3_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];

        state->r[15] += state->r[6];
        state->r[2] ^= state->r[15];
        state->r[14] = zander3_rotl((state->r[14] ^ state->r[12]), 9);
        state->r[4] += state->r[9];
        state->r[13] ^= state->r[11];
        state->r[6] = zander3_rotr((state->r[6] ^ state->r[10]), 6);
        state->r[12] += state->r[13];
        state->r[8] ^= state->r[8];
        state->r[11] = zander3_rotl((state->r[11] ^ state->r[3]), 11);
        state->r[10] += state->r[1];
        state->r[1] ^= state->r[4];
        state->r[3] = zander3_rotr((state->r[3] ^ state->r[7]), 7);
        state->r[5] += state->r[0];
        state->r[7] ^= state->r[2];
        state->r[9] = zander3_rotl((state->r[9] ^ state->r[0]), 3);
        state->r[0] += state->r[5];
    }
    state->o = 0;
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void z3gen_subkeys(struct zander3_state * state, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    struct z3ksa_state kstate;
    int c = 0;
    int i;
    int s;
    state->rounds = ((keylen / 4) + ((keylen / 8) + (48 - (keylen / 8))));
    memset(state->K, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->K2, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->K3, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->K4, 0, state->rounds*(2*sizeof(uint64_t)));
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
            zander3_F(&kstate);
            state->K[i][s] = 0;
	    state->K[i][s] = kstate.o;
        }
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_F(&kstate);
            state->K2[i][s] = 0;
	    state->K2[i][s] = kstate.o;
        }
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_F(&kstate);
            state->K3[i][s] = 0;
	    state->K3[i][s] = kstate.o;
        }
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 2; s++) {
            zander3_F(&kstate);
            state->K4[i][s] = 0;
	    state->K4[i][s] = kstate.o;
        }
    }
    for (s = 0; s < 4; s++) {
        zander3_F(&kstate);
        state->D[s] = 0;
        state->D[s] = kstate.o;
    }
}

uint64_t z3block_encrypt(struct zander3_state * state, uint64_t *xl, uint64_t *xr, uint64_t *xp, uint64_t *xq) {
    int i;
    uint64_t Xr, Xl, Xp, Xq, temp;

    Xl = *xl;
    Xr = *xr;
    Xp = *xp;
    Xq = *xq;

    for (i = 0; i < state->rounds; i++) {
/* Confusion */
        Xq += state->K[i][0];
        Xr += Xq + state->K[i][1];
        Xl = zander3_rotl(Xl, 18) ^ Xp;

        Xp += state->K[i][2];
        Xl += Xp + state->K[i][3];
        Xq = zander3_rotl(Xq, 26) ^ Xr;

        Xr += Xq + t0;
        Xl += Xp + state->K2[i][0];
        Xp = zander3_rotl(Xp, 14) ^ Xl;

        Xq += state->K2[i][1];
        Xp += Xq;
        Xr = zander3_rotl(Xr, 16) ^ Xq;
        
        Xl += state->K2[i][2];
        Xr += Xl;
        Xq = zander3_rotl(Xq, 34) ^ Xp;

        Xr += state->K2[i][3];
        Xp += Xq;
        Xl = zander3_rotl(Xl, 28) ^ Xq;

        Xp += Xl;
        Xq += Xr;
        Xr = zander3_rotl(Xr, 22) ^ Xl;

        Xq += Xp;
        Xl += Xr;
        Xp = zander3_rotl(Xp, 46) ^ Xr;
 
/* Diffusion */

        Xl = zander3_rotr(Xl, 46);
        Xl += Xq;
        Xl ^= state->K4[i][0];

        Xr = zander3_rotr(Xr, 34);
        Xr += Xp + t1;
        Xr ^= state->K4[i][1];

        Xp = zander3_rotl(Xp, 4);
        Xp ^= Xr;
        
        Xq = zander3_rotl(Xq, 6);
        Xq ^= Xl;

        Xl += state->K3[i][2];
        Xr += state->K3[i][3];
        Xp += state->K3[i][1];
        Xq += state->K3[i][0];

    }
    *xl = Xl + state->D[3];
    *xr = Xr + state->D[2];
    *xp = Xp + state->D[1]; 
    *xq = Xq + state->D[0];

}

uint64_t z3block_decrypt(struct zander3_state * state, uint64_t *xl, uint64_t *xr, uint64_t *xp, uint64_t *xq) {
    int i;
    uint64_t Xr, Xl, Xp, Xq, temp;
    
    Xl = *xl;
    Xr = *xr;
    Xp = *xp;
    Xq = *xq;
    Xl -= state->D[3];
    Xr -= state->D[2];
    Xp -= state->D[1];
    Xq -= state->D[0];

    for (i = (state->rounds - 1); i != -1; i--) {
/* Diffusion */

        Xq -= state->K3[i][0];
        Xp -= state->K3[i][1];
        Xr -= state->K3[i][3];
        Xl -= state->K3[i][2];

        Xq ^= Xl;
        Xq = zander3_rotr(Xq, 6);

        Xp ^= Xr;
        Xp = zander3_rotr(Xp, 4);

        Xr ^= state->K4[i][1];
        Xr -= Xp + t1;
        Xr = zander3_rotl(Xr, 34);

        Xl ^= state->K4[i][0];
        Xl -= Xq;
        Xl = zander3_rotl(Xl, 46);

/* Confusion */

        temp = Xp ^ Xr;
        Xp = zander3_rotr(temp, 46);
        Xl -= Xr;
        Xq -= Xp;

        temp = Xr ^ Xl;
        Xr = zander3_rotr(temp, 22);
        Xq -= Xr;
        Xp -= Xl;

        temp = Xl ^ Xq;
        Xl = zander3_rotr(temp, 28);
        Xp -= Xq;
        Xr -= state->K2[i][3];

        temp = Xq ^ Xp;
        Xq = zander3_rotr(temp, 34);
        Xr -= Xl;
        Xl -= state->K2[i][2];

        temp = Xr ^ Xq;
        Xr = zander3_rotr(temp, 16);
        Xp -= Xq;
        Xq -= state->K2[i][1];

        temp = Xp ^ Xl;
        Xp = zander3_rotr(temp, 14);
        Xl -= Xp + state->K2[i][0];
        Xr -= Xq + t0;

     
        temp = Xq ^ Xr;
        Xq = zander3_rotr(temp, 26);
        Xl -= Xp + state->K[i][3];
        Xp -= state->K[i][2];

        temp = Xl ^ Xp;
        Xl = zander3_rotr(temp, 18);
        Xr -= Xq + state->K[i][1];
        Xq -= state->K[i][0];

        
    }
    *xl = Xl;
    *xr = Xr;
    *xp = Xp;
    *xq = Xq;
    
}

void * zander3_cbc_encrypt_kf(unsigned char * sk, unsigned long long sklen, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int keywrap_ivlen, int bufsize, unsigned char * password) {
    int password_len = strlen((char*)password);
    FILE *outfile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    amagus_random(&iv, nonce_length);
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, password_len, key, key_length, kdf_salt, strlen((char*)kdf_salt), kdf_iterations);
    unsigned char *kwnonce[keywrap_ivlen];
    key_wrap_encrypt(keyprime, key_length, key, K, kwnonce);
    outfile = fopen(outputfile, "wb");
    fwrite(kwnonce, 1, keywrap_ivlen, outfile);
    fwrite(iv, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);

    struct zander3_state state;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocksize = 32;
    uint64_t blocks = sklen / bufsize;
    int extrabytes = blocksize - (sklen % blocksize);
    int extra = sklen % bufsize;
    int v = blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    if (sklen < bufsize) {
        blocks = 1;
    }
    int pos = 0;
    int c = 0;
    int b;
    int r, m;
    uint64_t i;
    z3gen_subkeys(&state, keyprime, key_length, iv, nonce_length);
    for (i = 0; i < blocks; i++) {
        /*
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        } */
        c = 0;
	if ((i == (blocks - 1)) && (extra != 0)) {
            for (int p = 0; p < extrabytes; p++) {
                buffer[(bufsize-1-p)] = (unsigned char *)extrabytes;
	    }
            //bufsize = bufsize + extrabytes;
            for (int r = 0; r < (bufsize-extrabytes); r++) {
                buffer[r] = sk[pos];
                pos += 1;
            }
	}
        else {
            for (int r = 0; r < bufsize; r++) {
                buffer[r] = sk[pos];
                pos += 1;
            }
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
            xp = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
            xq = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
       
	    xl = xl ^ state.last[0];
	    xr = xr ^ state.last[1];
	    xp = xp ^ state.last[2];
	    xq = xq ^ state.last[3];

            z3block_encrypt(&state, &xl, &xr, &xp, &xq);

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
    fclose(outfile);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen((char*)kdf_salt), kdf_iterations);
    ganja_hmac(outputfile, ".tmp", mac_key, key_length);
}

void * zander3_cbc_decrypt_kf(char * inputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int keywrap_ivlen, int bufsize, unsigned char * password, unsigned char * pk, unsigned long long pklen, unsigned char * sk, unsigned long long sklen,  unsigned char * Spk, unsigned long long Spklen, unsigned char * Ssk, unsigned long long Ssklen) {
    int password_len = strlen((char*)password);
    FILE *infile;
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[nonce_length];
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *kwnonce[keywrap_ivlen];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    int datalen = ftell(infile);

    datalen = datalen - key_length - mac_length - nonce_length - keywrap_ivlen;
    int extrabytes = 32 - (datalen % 32);
    fseek(infile, 0, SEEK_SET);

    fread(&mac, 1, mac_length, infile);
    fread(kwnonce, 1, keywrap_ivlen, infile);
    fread(iv, 1, nonce_length, infile);
    fread(keyprime, 1, key_length, infile);
    int password_length = strlen((char*)password);
    manja_kdf(password, strlen((char*)password), key, key_length, kdf_salt, strlen((char*)kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen((char*)kdf_salt), kdf_iterations);
    key_wrap_decrypt(keyprime, key_length, key, kwnonce);

    struct zander3_state state;
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
    int pos = 0;
    uint64_t i;
    fclose(infile);
    unsigned char * keyblob = (unsigned char *) malloc(pklen+Spklen+sklen+Ssklen);
    if (ganja_hmac_verify(inputfile, mac_key, key_length) == 0) {
        infile = fopen(inputfile, "rb");
        fseek(infile, (mac_length + keywrap_ivlen + nonce_length + key_length), SEEK_SET);
        z3gen_subkeys(&state, keyprime, key_length, iv, nonce_length);
        for (i = 0; i < blocks; i++) {
            if (i == (blocks - 1) && (extra != 0)) {
                bufsize = extra;
            }
            fread(&buffer, 1, bufsize, infile);
            c = 0;
            xl = ((uint64_t)buffer[c] << 56) + ((uint64_t)buffer[c+1] << 48) + ((uint64_t)buffer[c+2] << 40) + ((uint64_t)buffer[c+3] << 32) + ((uint64_t)buffer[c+4] << 24) + ((uint64_t)buffer[c+5] << 16) + ((uint64_t)buffer[c+6] << 8) + (uint64_t)buffer[c+7];
            xr = ((uint64_t)buffer[c+8] << 56) + ((uint64_t)buffer[c+9] << 48) + ((uint64_t)buffer[c+10] << 40) + ((uint64_t)buffer[c+11] << 32) + ((uint64_t)buffer[c+12] << 24) + ((uint64_t)buffer[c+13] << 16) + ((uint64_t)buffer[c+14] << 8) + (uint64_t)buffer[c+15];
            xp = ((uint64_t)buffer[c+16] << 56) + ((uint64_t)buffer[c+17] << 48) + ((uint64_t)buffer[c+18] << 40) + ((uint64_t)buffer[c+19] << 32) + ((uint64_t)buffer[c+20] << 24) + ((uint64_t)buffer[c+21] << 16) + ((uint64_t)buffer[c+22] << 8) + (uint64_t)buffer[c+23];
            xq = ((uint64_t)buffer[c+24] << 56) + ((uint64_t)buffer[c+25] << 48) + ((uint64_t)buffer[c+26] << 40) + ((uint64_t)buffer[c+27] << 32) + ((uint64_t)buffer[c+28] << 24) + ((uint64_t)buffer[c+29] << 16) + ((uint64_t)buffer[c+30] << 8) + (uint64_t)buffer[c+31];
        
	    state.next[0] = xl;
	    state.next[1] = xr;
	    state.next[2] = xp;
	    state.next[3] = xq;

            z3block_decrypt(&state, &xl, &xr, &xp, &xq);
       
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
            for (int pi = 0; pi < bufsize; pi++) {
                keyblob[pos] = buffer[pi];
                pos += 1;
            }
        }
        fclose(infile);
        pos = 0;
        for (int pi = 0; pi < pklen; pi++) {
            pk[pi] = keyblob[pos];
            pos += 1;
        }
        for (int pi = 0; pi < sklen; pi++) {
            sk[pi] = keyblob[pos];
            pos += 1;
        }
        for (int pi = 0; pi < Spklen; pi++) {
            Spk[pi] = keyblob[pos];
            pos += 1;
        }
        for (int pi = 0; pi < Ssklen; pi++) {
            Ssk[pi] = keyblob[pos];
            pos += 1;
        }
        free(keyblob);

    }    
    else {
        printf("Error: Secret key has been tampered with.\n");
        free(keyblob);
        exit(-1);
    }
}

void * zander3_cbc_encrypt(char *keyfile1, char *keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len,  int bufsize, unsigned char * passphrase) {
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

    struct zander3_state state;
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
    z3gen_subkeys(&state, key, key_length, iv, nonce_length);
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

            z3block_encrypt(&state, &xl, &xr, &xp, &xq);

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

void * zander3_cbc_decrypt(char * keyfile1, char * keyfile2, char * inputfile, char *outputfile, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, int salt_len, int password_len, int bufsize, unsigned char * passphrase) {
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

    struct zander3_state state;
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
        z3gen_subkeys(&state, key, key_length, iv, nonce_length);
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

                z3block_decrypt(&state, &xl, &xr, &xp, &xq);
        
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
