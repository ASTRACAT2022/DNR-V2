CC=gcc
CFLAGS=-I/usr/include/ldns -g -Wall
LDFLAGS=-lldns -lcrypto

TARGET=dnr-server

all: $(TARGET)

$(TARGET): dnr-server.c
	$(CC) $(CFLAGS) -o $(TARGET) dnr-server.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o