OPENSLL_INSTALL_DIR=/home/pirug/openssl
IOTA_DIR=/home/pirug/Desktop/iota.c
OPENSSL_LIB=lib64

CC = gcc
CFLAGS  +=\
-I $(OPENSLL_INSTALL_DIR)/include/ \
-I $(IOTA_DIR)/build/include/ \
-I $(IOTA_DIR)/build/include/cjson/ \
-I $(IOTA_DIR)/build/include/client/ \
-I $(IOTA_DIR)/build/include/crypto/ \
-I $(IOTA_DIR)/build/include/core/ \
-I $(IOTA_DIR)/build/include/client/api/v1/\
-L $(IOTA_DIR)/build/lib/\
-Wall -fPIC -g \

LDFLAGS= -shared -ldl -lm -liota_crypto -liota_core -liota_client -lcurl -lsodium\

TARGET = libssiprovider.so
SOURCES = ssiprov.c ssiprov.h did/ott.c did/ott_internal.c did/ott_internal.h did/ott_primitives.c did/ott_primitives.h vc/dm2.c vc/dm2_internal.h vc/dm2_internal.c cJSON.c cJSON.h 
OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC)  $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f ssiprov.o ott.o ott_internal.o ott_primitives.o dm2.o dm2_internal.o cJSON.o libssiprovider.so

install:
	
	cp libssiprovider.so $(OPENSLL_INSTALL_DIR)/$(OPENSSL_LIB)/ossl-modules/ssi.so

uninstall:
	rm -f $(OPENSLL_INSTALL_DIR)/$(OPENSSL_LIB)/ossl-modules/ssi.so

tests:
	chmod -R 777 ./test
