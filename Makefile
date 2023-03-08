CC      = gcc
CFLAGS  +=\
-I/home/ale/iota.c/build/include/ \
-I/home/ale/iota.c/build/include/cjson/ \
-I/home/ale/iota.c/build/include/client/ \
-I/home/ale/iota.c/build/include/crypto/ \
-I/home/ale/iota.c/build/include/core/ \
-I/home/ale/iota.c/build/include/client/api/v1/\
-L/home/ale/iota.c/build/lib/\
-Wall -fPIC -g \


LDFLAGS= -shared -lssl -lcrypto -lsodium -ldl -lm -lcurl -liota_crypto -liota_core -liota_client -lcurl -lsodium \

TARGET  = libdidprovider.so
SOURCES = didprovider.c didprovider.h CRUD.c did_method.c did_method.h OTT_def.h OTT.c ott-wrapper.c cJSON.c cJSON.h 
OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC)  $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f didprovider.o did_method.o ott-wrapper.o CRUD.o OTT.o cJSON.o

install:
	
	sudo mv libdidprovider.so /usr/local/lib64/ossl-modules/didprovider.so

uninstall:
	sudo rm -f /usr/local/lib64/ossl-modules/didprovider.so

tests:
	chmod -R 777 ./test