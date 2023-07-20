OPENSSL_DIR=/home/pirug/openssl

CC = gcc
CFLAGS = -Wall -g
CPPFLAGS = -I $(OPENSSL_DIR)/include/
LDFLAGS = \
-Wl,-rpath=$(OPENSSL_DIR)/lib64/ \
-L $(OPENSSL_DIR)/lib64/ \

LDLIBS = -lssl -lcrypto

SOURCES = did-resolve-demo.c
TARGET = did-resolve-demo

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)

clean: 
	rm -f $(TARGET)