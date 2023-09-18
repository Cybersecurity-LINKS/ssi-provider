OPENSSL_DIR=/home/ale/Scrivania/openssl
IOTA_DIR=/home/ale/Scrivania/iota.c
OPENSSL_LIB=lib64

CC      = gcc
CFLAGS  +=\
-I $(OPENSSL_DIR)/include/ \
-I $(IOTA_DIR)/build/include/ \
-I $(IOTA_DIR)/build/include/cjson/ \
-I $(IOTA_DIR)/build/include/client/ \
-I $(IOTA_DIR)/build/include/crypto/ \
-I $(IOTA_DIR)/build/include/core/ \
-I $(IOTA_DIR)/build/include/client/api/v1/\
-L $(IOTA_DIR)/build/lib/\
-Wall -fPIC -g \

LDFLAGS= -shared -ldl -lm -liota_crypto -liota_core -liota_client -lcurl -lsodium\

TARGET  = libssiprovider.so
SOURCES = ssiprovider.c ssiprovider.h did.c did_internal.c did_internal.h vc_internal.h vc_internal.c vc.c OTT_def.h OTT.c OTT.h cJSON.c cJSON.h 
OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC)  $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f ssiprovider.o did.o did_internal.o vc.o vc_internal.o OTT.o cJSON.o libssiprovider.so

install:
	
	cp libssiprovider.so $(OPENSSL_DIR)/$(OPENSSL_LIB)/ossl-modules/ssi.so

uninstall:
	rm -f $(OPENSSL_DIR)/$(OPENSSL_LIB)/ossl-modules/ssi.so

tests:
	chmod -R 777 ./test
