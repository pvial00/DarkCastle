from qloqX import encrypt, decrypt, oaep_encrypt, oaep_decrypt, sign, verify
from qapla import crypt
import sys
from os import urandom
from Crypto.Util import number

# usage:
# python qloqX_qaplay.py e <input file> <output file> <public key file> <secret key file>
# python qloqX_qaplay.py d <input file> <output file> <secret key file> <public key file>
keylen = 32
noncelen = 16
# This made to be used with 1536 bit keys
Klen = 384
Ylen = 384
Slen = 384
mode = sys.argv[1]
infile = sys.argv[2]
outfile = sys.argv[3]
keyfile = sys.argv[4]
keyfile2 = sys.argv[5]

class QLOQKeys:
    def __init__(self, filename):
        f = open(filename, "r")
        blob = f.read()
        f.close()
        lines = blob.split('\n')
        self.key = long(lines[0].split(':')[1].strip())
        self.n = long(lines[1].split(':')[1].strip())
        self.M = long(lines[2].split(':')[1].strip())

qk1 = QLOQKeys(keyfile)
qk2 = QLOQKeys(keyfile2)

if mode == "e":
    f = open(infile, "r")
    msg = f.read()
    f.close()
    keyP = urandom(keylen)
    nonce = urandom(noncelen)
    KP = number.bytes_to_long(keyP)
    X, Y = oaep_encrypt(KP, qk1.M)
    K = encrypt(X, qk1.key, qk1.n, qk1.M)
    S = sign(K, qk2.key, qk2.n, qk2.M)
    y = number.long_to_bytes(Y)
    x = number.long_to_bytes(K)
    s = number.long_to_bytes(S)
    ctxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(s+x+y+nonce+ctxt)
    f.close()
elif mode == "d":
    f = open(infile, "r")
    data = f.read()
    f.close()
    S = data[:Slen]
    X = data[Slen:Slen+Klen]
    x = number.bytes_to_long(X)
    Y = data[Slen+Klen:Slen+Ylen+Klen]
    nonce = data[Slen+Klen+Ylen:Slen+Klen+Ylen+noncelen]
    msg = data[Slen+Klen+Ylen+noncelen:len(data)]
    K = decrypt(x, qk1.key, qk1.n, qk1.M)
    KP = oaep_decrypt(number.long_to_bytes(K), Y)
    keyP = number.long_to_bytes(KP)
    if verify(K, x, qk2.key, qk2.n, qk2.M) == False:
        print "Signing verification failed.  Message is not authentic."
        exit(1)
    ptxt = crypt(msg, keyP, nonce)
    f = open(outfile, "w")
    f.write(ptxt)
    f.close()
