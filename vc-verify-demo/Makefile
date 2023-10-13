OPENSSL_DIR=path/to/openssl
OPENSSL_LIB=lib64

CC = gcc
CFLAGS = -Wall -g
CPPFLAGS = -I $(OPENSSL_DIR)/include/
LDFLAGS = \
-Wl,-rpath=$(OPENSSL_DIR)/$(OPENSSL_LIB)/ \
-L $(OPENSSL_DIR)/$(OPENSSL_LIB)/ \

LDLIBS = -lssl -lcrypto

SOURCES = vc-verify-demo.c
TARGET = vc-verify-demo

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)

clean: 
	rm -f $(TARGET)
