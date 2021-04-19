CC=gcc
CFLAGS=-O3 -std=c99 -w -lsodium -std=c99
TARGET=castle
KEYGEN=castle-keygen
all: $(TARGET) $(KEYGEN)

$(TARGET): castle.c
	$(CC) castle.c $(CFLAGS) -o $(TARGET)

$(KEYGEN): castle_keygen.c
	$(CC) castle_keygen.c $(CFLAGS) -o $(KEYGEN)

clean:
	$(RM) $(TARGET) $(RM) $(KEYGEN)
