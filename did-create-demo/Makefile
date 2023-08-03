OPENSSL_DIR=/home/pirug/openssl
TESTS_DIR=$(HOME)/Desktop/tests/id-gen/

CC = gcc
CFLAGS = -Wall -g
CPPFLAGS = -I $(OPENSSL_DIR)/include/
LDFLAGS = \
-Wl,-rpath=$(OPENSSL_DIR)/lib64/ \
-L $(OPENSSL_DIR)/lib64/ \

LDLIBS = -lssl -lcrypto

SOURCES = did-create-demo.c
TARGET = did-create-demo

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)
	
clean:
	rm -f $(TARGET) create_mainnet.txt resolve_mainnet.txt update_mainnet.txt revoke_mainnet.txt channel.txt
	
install:
	cp $(TARGET) $(TEST_DIR)
