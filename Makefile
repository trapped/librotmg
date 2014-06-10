.PHONY: all
all: | lib client echo

.PHONY: client
client:
	gcc -g -Wall client.c -lm -ledit -L. -lrotmg -o client

.PHONY: lib
lib: | utils rc4 rsa packets rotmg
	gcc -g -shared -Wl,-soname,librotmg.so -lm -lssl -lcrypto -o librotmg.so *.o packets/*.o
	cp ./librotmg.so /usr/lib

.PHONY: rc4
rc4:
	gcc -g -c -fPIC rc4.c -o rc4.o

.PHONY: rsa
rsa:
	gcc -g -c -fPIC rsa.c -o rsa.o

.PHONY: utils
utils:
	gcc -g -c -fPIC utils.c -o utils.o

.PHONY: packets
packets: | utils rc4
	gcc -g -c -fPIC packets/hello.c -o packets/hello.o
	gcc -g -c -fPIC packets/failure.c -o packets/failure.o

.PHONY: rotmg
rotmg: | rc4 utils packets
	gcc -g -c -fPIC rotmg.c -o rotmg.o

.PHONY: echo
echo:
	gcc -g  -Wall echosrv.c -lm -o echosrv

.PHONY: clean
clean:
	rm -rf *.o packets/*.o *.so client echosrv
	rm -rf /usr/lib/librotmg.so
