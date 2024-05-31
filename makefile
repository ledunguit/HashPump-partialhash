CC=g++
CFLAGS=-c -Wall
INSTALLLOCATION=/usr/bin/
LIB=lib
INCLUDE=openssl

all: hashpump

hashpump: main.o Extender.o MD4ex.o MD5ex.o SHA1.o SHA256.o SHA512ex.o
	$(CC) main.o Extender.o MD4ex.o MD5ex.o SHA1.o SHA256.o SHA512ex.o -I$(INCLUDE) -L$(LIB) -lcrypto -o hashpump

main.o:
	$(CC) $(CFLAGS) main.cpp

Extender.o:
	$(CC) $(CFLAGS) Extender.cpp

MD4ex.o:
	$(CC) $(CFLAGS) MD4ex.cpp

MD5ex.o:
	$(CC) $(CFLAGS) MD5ex.cpp

SHA1.o:
	$(CC) $(CFLAGS) SHA1.cpp

SHA256.o:
	$(CC) $(CFLAGS) SHA256.cpp

SHA512ex.o:
	$(CC) $(CFLAGS) SHA512ex.cpp

clean:
	rm *.o hashpump

install: hashpump
	cp hashpump $(INSTALLLOCATION)
