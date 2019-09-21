#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int keywrap128_ivlen = 16;
int keywrap256_ivlen = 16;
int keywrap512_ivlen = 16;
int keywrap1024_ivlen = 16;

void * key_wrap_encrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * K, unsigned char * nonce) {
    if (key_length == 128) {
        amagus_random(keyprime, key_length);
        amagus_random(nonce, keywrap1024_ivlen);
        memcpy(K, keyprime, key_length);
        amagus1_crypt(K, key, key_length, nonce, key_length);
        for (int i = 0; i < key_length; i++) {
            K[i] = K[i] ^ key[i];
        }
    }
    else if (key_length == 64) {
        amagus_random(keyprime, key_length);
        amagus_random(nonce, keywrap512_ivlen);
        memcpy(K, keyprime, key_length);
        amagus1_crypt(K, key, key_length, nonce, key_length);
        for (int i = 0; i < key_length; i++) {
            K[i] = K[i] ^ key[i];
        }
    }
    else if (key_length == 32) {
        amagus_random(keyprime, key_length);
        amagus_random(nonce, keywrap256_ivlen);
        memcpy(K, keyprime, key_length);
        uvajda1_crypt(K, key, nonce, key_length);
        for (int i = 0; i < key_length; i++) {
            K[i] = K[i] ^ key[i];
        }
    }
}

void * key_wrap_decrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * nonce) {
    if (key_length == 128) {
        for (int i = 0; i < key_length; i++) {
            keyprime[i] = keyprime[i] ^ key[i];
        }
        amagus1_crypt(keyprime, key, key_length, nonce, key_length);
    }
    else if (key_length == 64) {
        for (int i = 0; i < key_length; i++) {
            keyprime[i] = keyprime[i] ^ key[i];
        }
        amagus1_crypt(keyprime, key, key_length, nonce, key_length);
    }
    else if (key_length == 32) {
        for (int i = 0; i < key_length; i++) {
            keyprime[i] = keyprime[i] ^ key[i];
        }
        uvajda1_crypt(keyprime, key, nonce, key_length);
    }
}
