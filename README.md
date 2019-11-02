# DarkCastle

*** Warning the ciphers contained in this program are still undergoing cryptanalysis

*** Warning: this product is for non-production use.  If you want production level crypto, use OpenSSL or libsodium

*** This program may be used to encrypt arbitrary file sizes

DarkCastle is an authenticated file encryption program aiming to provide a large collection of community ciphers.  This program is intended for educational use until full cryptanalysis can be completed.

Please note these are efficient file encryption functions that buffer inputfile and write to the output file simultaneously

DarkCastle is accepting ciphers.  Email pvial00@gmail.com or open a github issue to submit/integrate a cipher, hash function, KDF or authentication method.

Complimenting DarkCastle is DarkPass, a password generator designed to give secure passwords compatible with DarkCastle.

https://github.com/pvial00/DarkPass

*** Tested on MacOS, FreeBSD, Linux, Solaris, OpenBSD, NetBSD

# Q'loQX Castle

*** Requires pycrypto

Q'loQX Castle is a Python wrapper around DarkCastle providing authenticated public key encryption.

Q'loQX Castle requires DarkCastle and DarkPass.  DarkCastle is used for symmentric file encryption and message authentication.  DarkPass is for password generation.  castle.py then uses Q'loQX to share a 128 character password between two people.  The program is meant to share small files over email.  It is meant to work with 3072 bit QX keys.  Recommended DarkCastle cipher is zanderfish3 which uses a 256 bit key.



# Algorithms and authenticators

All ciphers, with the exception of Specjal and Zywca which are still undergoing testing, are recommended ciphers.  The top two recommended stream ciphers are Qapla and Amagus and the top two block ciphers are ZanderFish3 and ZanderFish2.

Fastest cipher is Uvajda

Uvajda 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Uvajda

Amagus 256/512/1024 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Amagus

Dark 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/DarkCipher

Zanderfish2 256 bit authenticated with Ganja 256 bit - 128 bit IV length

https://github.com/pvial00/Zanderfish2

Zanderfish3 256 bit authenticated with Ganja 256 bit - 256 bit IV length

https://github.com/pvial00/Zanderfish3

Spock-CBC 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Spock

Specjal-CBC 256/512/1024 bit authenticated with Ganja 256 bit - 256 bit IV length

https://github.com/pvial00/Specjal

Qapla 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Qapla
