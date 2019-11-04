CC=gcc
CFLAGS=-O3 -w -lssl -lcrypto -std=c99 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
TARGET=castle
all: $(TARGET)

$(TARGET): castle.c
	$(CC) castle.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
