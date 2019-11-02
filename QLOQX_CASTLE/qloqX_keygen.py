from qloqX import keygen
import sys

try:
    prefix = sys.argv[1]
except IndexError as ier:
    prefix = "qloq"

sk, pk, n, M = keygen()
pkfile = prefix + ".pk"
skfile = prefix + ".sk"
pkdata = "Public key:" + str(pk) + "\n" + "Modulus:" + str(n) + "\n" + "Mask:" + str(M)
skdata = "Secret key:" + str(sk) + "\n" + "Modulus:" + str(n) + "\n" + "Mask:" + str(M)
f = open(pkfile, "w")
f.write(pkdata)
f.close()
f = open(skfile, "w")
f.write(skdata)
f.close()
