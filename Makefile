.PHONY: all
all: | lib client echo

.PHONY: client
client:
	gcc -std=c99 -g -Wall client.c -lm -ledit -L. -lrotmg -o client

.PHONY: lib
lib:
	# rc4
	gcc -std=c99 -g -c -fPIC rc4.c -o rc4.o
	# utils
	gcc -std=c99 -g -c -fPIC utils.c -o utils.o
	# packets
	gcc -std=c99 -g -c -fPIC packets.c -o packets.o
	# rotmg
	gcc -std=c99 -g -c -fPIC rotmg.c -o rotmg.o
	# librotmg (link)
	gcc -std=c99 -g -shared -Wl,-soname,librotmg.so -lm -o librotmg.so rotmg.o rc4.o utils.o packets.o

	cp ./librotmg.so /usr/lib

.PHONY: echo
echo:
	gcc -std=c99 -g  -Wall echosrv.c -lm -o echosrv

.PHONY: clean
clean:
	rm -rf *.o *.so client echosrv
	rm -rf /usr/lib/librotmg.so