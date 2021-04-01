CC=gcc
CFLAGS=-O3 -std=c99 -w -lssl -lcrypto -std=c99 -I/opt/homebrew/opt/openssl@1.1/include -L/opt/homebrew/opt/openssl@1.1/lib
TARGET=castle
KEYGEN=castle-keygen
all: $(TARGET) $(KEYGEN)

$(TARGET): castle.c
	$(CC) castle.c $(CFLAGS) -o $(TARGET)

$(KEYGEN): qloq_keygen.c
	$(CC) qloq_keygen.c $(CFLAGS) -o $(KEYGEN)

clean:
	$(RM) $(TARGET) $(RM) $(KEYGEN)
