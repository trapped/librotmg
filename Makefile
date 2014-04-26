.PHONY: all
all: | lib client echo

.PHONY: client
client:
	gcc -std=c99 -g -Wall client.c -lm -ledit -L. -lrotmg -o client

.PHONY: lib
lib:
	# librc4
	#gcc -std=c99 -g -c fPIC rc4.c -o rc4.o
	# librotmg
	gcc -std=c99 -g -c -fPIC rotmg.c -lm -o rotmg.o
	gcc -std=c99 -g -shared -Wl,-soname,librotmg.so -lm -o librotmg.so rotmg.o
	cp ./librotmg.so /usr/lib

.PHONY: echo
echo:
	gcc -std=c99 -g  -Wall echosrv.c -lm -o echosrv

.PHONY: clean
clean:
	rm -rf *.o *.so client echosrv
	rm -rf /usr/lib/librotmg.so