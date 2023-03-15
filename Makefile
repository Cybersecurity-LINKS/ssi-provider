OPENSSL_DIR=/home/pirug/openssl
IOTA_DIR=/home/pirug/Desktop/iota.c

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

TARGET  = libdidprovider.so
SOURCES = didprovider.c didprovider.h CRUD.c did_method.c did_method.h OTT_def.h OTT.c ott-wrapper.c cJSON.c cJSON.h 
OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC)  $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f didprovider.o did_method.o ott-wrapper.o CRUD.o OTT.o cJSON.o libdidprovider.so

install:
	
	cp libdidprovider.so $(OPENSSL_DIR)/lib64/ossl-modules/didprovider.so

uninstall:
	rm -f $(OPENSSL_DIR)/lib64/ossl-modules/didprovider.so

tests:
	chmod -R 777 ./test
