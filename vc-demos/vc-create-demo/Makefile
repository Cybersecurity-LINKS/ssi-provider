OPENSLL_INSTALL_DIR=/home/pirug/openssl
OPENSSL_LIB=lib64


CC = gcc
CFLAGS = -Wall -g
CPPFLAGS = -I $(OPENSLL_INSTALL_DIR)/include/
LDFLAGS = \
-Wl,-rpath=$(OPENSLL_INSTALL_DIR)/$(OPENSSL_LIB)/ \
-L $(OPENSLL_INSTALL_DIR)/$(OPENSSL_LIB)/ \

LDLIBS = -lssl -lcrypto

SOURCES = vc-create-demo.c
TARGET = vc-create-demo

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)
	
clean:
	rm -f $(TARGET) vc.txt
