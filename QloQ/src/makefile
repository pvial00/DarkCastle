CC=gcc
CFLAGS=-O3 -std=c99 -w -lssl -lcrypto -std=c99 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
TARGET=qloq-keygen
all: $(TARGET)

$(TARGET): qloq_keygen.c
	$(CC) qloq_keygen.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
