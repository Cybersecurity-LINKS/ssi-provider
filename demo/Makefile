CC = gcc
CFLAGS = -Wall -g
CPPFLAGS = -I/home/pirug/openssl/include/
LDFLAGS = \
-Wl,-rpath=/home/pirug/openssl/lib64/ \
-L/home/pirug/openssl/lib64/ \

LDLIBS = -lssl -lcrypto

SOURCES = demo.c
TARGET = demo

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)
	
clean:
	rm -f $(TARGET) create_mainnet.txt resolve_mainnet.txt update_mainnet.txt revoke_mainnet.txt channel.txt
