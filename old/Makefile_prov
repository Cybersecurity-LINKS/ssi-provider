CC      = gcc
CFLAGS  +=\
-I/home/ale/Scaricati/iota.c-dev/build2/include/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/cjson/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/client/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/client/api/v1/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/crypto/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/core/ \
-L/home/ale/Scaricati/iota.c-dev/build2/lib/\
-Wall -fPIC -g \

LDFLAGS= -shared -lssl -lcrypto -lsodium -ldl -lm -lcurl -liota_crypto -liota_core -liota_client -lcurl -lsodium \

TARGET  = libdidprovider.so
SOURCES = didprovider.c didprovider.h CRUD.c did_method.c did_method.h WAM_def.h WAM.c wam-wrapper.c cJSON.c cJSON.h 
OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC)  $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f didprovider.o did_method.o wam-wrapper.o CRUD.o WAM.o

install:
	
	sudo mv libdidprovider.so /usr/local/lib64/ossl-modules/didprovider.so

uninstall:
	sudo rm -f /usr/local/lib64/ossl-modules/didprovider.so

tests:
	chmod -R 777 ./test