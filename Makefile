CC      = gcc
CFLAGS  +=\
-I /home/pirug/openssl/include/ \
-I iota.c/build/include/ \
-I iota.c/build/include/cjson/ \
-I iota.c/build/include/client/ \
-I iota.c/build/include/crypto/ \
-I iota.c/build/include/core/ \
-I iota.c/build/include/client/api/v1/\
-L iota.c/build/lib/\
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
	
	mv libdidprovider.so /home/pirug/openssl/lib64/ossl-modules/didprovider.so

uninstall:
	rm -f /home/pirug/openssl/lib64/ossl-modules/didprovider.so

tests:
	chmod -R 777 ./test
