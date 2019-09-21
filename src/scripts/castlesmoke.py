import subprocess, os, time, sys

# Smoke test all algorithms
#This script assumes that you have the castle, darkpass, ganjasum

inputfile = "testfile1"
testfile_size = 1048576
passlen = str(32)
# must be between 0 and 255
test_char = 0

def getkey(length):
    cmd = ['darkpass', length]
    k = subprocess.check_output(cmd)
    return k

def geninputfile():
    f = open(inputfile, "w")
    buf = []
    for x in xrange(testfile_size):
        buf.append(chr(test_char))
    f.write("".join(buf))
    f.close()

def getalgorithms():
    cmd = ['castle']
    out = subprocess.check_output(cmd)
    linestmp = out.split("\n")
    lines = linestmp[5:]
    algorithms = []
    for line in lines:
        if "bit" in line:
            algorithm = line.split()[0]
            algorithms.append(algorithm)
    return algorithms

geninputfile()
algorithms = getalgorithms()
algorithm_count = len(algorithms)
c = 0

for algorithm in algorithms:
    key = getkey(passlen)
    print key
    cmdenc = ['castle', algorithm, '-e', inputfile, '.b1' , key]
    try:
        out = subprocess.check_output(cmdenc)
    except subprocess.CalledProcessError as ier:
        print algorithm + " failed to encrypt"
    else: 
        print algorithm + " encrypting" + out
        cmdhash = ['ganjasum', inputfile]
        h1 = subprocess.check_output(cmdhash)
        cmddec = ['castle', algorithm, '-d', '.b1','.b2' , key]
        out = subprocess.check_output(cmddec)
        print algorithm + " decrypting" + out
        cmdhash = ['ganjasum', '.b2']
        h2 = subprocess.check_output(cmdhash)
        if h1 != h2:
            print inputfile + " failed to decrypt!"
        else:
           c += 1
if c == algorithm_count:
    print "Success all algorithms check out"
else:
    print "One or more algorithms failed"
cmdrm = ['rm', inputfile]
out = subprocess.check_output(cmdrm)
cmdrm = ['rm', '.b1']
out = subprocess.check_output(cmdrm)
cmdrm = ['rm', '.b2']
out = subprocess.check_output(cmdrm)
