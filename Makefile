CC = gcc
CFLAGS = -Wall -g

SOURCE_1 = did_method.c
SOURCE_2 = WAM.c 
SOURCE_3 = wam-wrapper.c


#LDFLAGS+=\
-I/home/ale/iota.c/build/include/ \
-I/home/ale/iota.c/build/include/cjson/ \
-I/home/ale/iota.c/build/include/client/ \
-I/home/ale/iota.c/build/include/crypto/ \
-I/home/ale/iota.c/build/include/core/ \

LDFLAGS+=\
-I/home/ale/Scaricati/iota.c-dev/build2/include/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/cjson/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/client/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/client/api/v1/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/crypto/ \
-I/home/ale/Scaricati/iota.c-dev/build2/include/core/ \
-L/home/ale/Scaricati/iota.c-dev/build2/lib/\

LDFLAGS += \
-L/home/ale/iota.c/build/lib/ \
-liota_crypto -lcrypto -liota_core -liota_client -lcjson -lcurl -lsodium

APP = did_method

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SOURCE_1) $(SOURCE_2) $(SOURCE_3) -o $(APP) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(APP) *.o