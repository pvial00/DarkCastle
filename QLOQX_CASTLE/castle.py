from qloqX import encrypt, decrypt, oaep_encrypt, oaep_decrypt, sign, verify
import sys, subprocess
from Crypto.Util import number

# prerequisites:
# DarkCastle, DarkPass

# usage:
# python castle.py e <algorithm>  <input file> <output file> <public key file> <secret key file>
# python castle.py d <algorithm> <input file> <output file> <secret key file> <public key file>
# This made to be used with 1536 bit keys
Klen = 384
Ylen = 384
Slen = 384
passlen = 128
mode = sys.argv[1]
algorithm = sys.argv[2]
infile = sys.argv[3]
outfile = sys.argv[4]
keyfile = sys.argv[5]
keyfile2 = sys.argv[6]

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
    pass_cmd = ['darkpass', str(passlen)]
    passtmp = subprocess.check_output(pass_cmd)
    password = passtmp[:len(passtmp) -1]
    P = number.bytes_to_long(password)
    enc_cmd = ['castle', algorithm, '-e', infile, outfile, password]
    out = subprocess.check_output(enc_cmd)
    f = open(outfile, "r")
    ctxt = f.read()
    f.close()
    X, Y = oaep_encrypt(P, qk1.M)
    K = encrypt(X, qk1.key, qk1.n, qk1.M)
    S = sign(K, qk2.key, qk2.n, qk2.M)
    y = number.long_to_bytes(Y)
    x = number.long_to_bytes(K)
    s = number.long_to_bytes(S)
    f = open(outfile, "w")
    f.write(s+x+y+ctxt)
    f.close()
elif mode == "d":
    f = open(infile, "r")
    data = f.read()
    f.close()
    S = data[:Slen]
    X = data[Slen:Slen+Klen]
    x = number.bytes_to_long(X)
    Y = data[Slen+Klen:Slen+Ylen+Klen]
    ctxt = data[Slen+Klen+Ylen:len(data)]
    K = decrypt(x, qk1.key, qk1.n, qk1.M)
    P = oaep_decrypt(number.long_to_bytes(K), Y)
    if verify(K, x, qk2.key, qk2.n, qk2.M):
        f = open(infile, "w")
        f.write(ctxt)
        f.close()
        password = number.long_to_bytes(P)
        dec_cmd = ['castle', algorithm, '-d', infile, outfile, password]
        out = subprocess.check_output(dec_cmd)
        if "Error" in out:
            print out
    else:
        print "Signing verification failed.  Message is not authentic."
