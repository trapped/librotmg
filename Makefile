.PHONY: lib
lib:
	gcc -std=c99 -c -fPIC librotmg.c -lm -o librotmg.o
	gcc -std=c99 -shared -Wl,-soname,librotmg.so -lm -o librotmg.so librotmg.o
	#cp ./librotmg.so /usr/lib