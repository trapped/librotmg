#include <stdlib.h>

char*          reverse_endian (long length, char* buffer);
unsigned char* ltoc           (long num);
long           ctol           (unsigned char* buffer);
unsigned char* stoc           (short num);
short          ctos           (unsigned char* buffer);

char*
reverse_endian (long length, char* buffer)
{
	//char* swapped = ((buffer>>24)&0xff)	| // move byte 3 to byte 0
	//				((buffer<<8)&0xff0000) | // move byte 1 to byte 2
	//				((buffer>>8)&0xff00)	| // move byte 2 to byte 1
	//				((buffer<<24)&0xff000000); // byte 0 to byte 3

	char* temp = malloc(sizeof(char) * length);
	for(int i = 0; i < length; i++) {
		temp[i] = buffer[length - i - 1];
	}
	return temp;
}

unsigned char*
ltoc (long num)
{
	unsigned char* temp = malloc(sizeof(char)*4);
	temp[0] = num;
	temp[1] = num >> 8;
	temp[2] = num >> 16;
	temp[3] = num >> 24;
	return temp;
}

long
ctol (unsigned char* buffer)
{
	long temp = 0;
	temp += buffer[0];
	temp += buffer[1] << 8;
	temp += buffer[2] << 16;
	temp += buffer[3] << 24;
	return temp;
}

unsigned char*
stoc (short num)
{
	unsigned char* temp = malloc(sizeof(char)*2);
	temp[0] = num;
	temp[1] = num >> 8;
	return temp;
}

short
ctos (unsigned char* buffer)
{
	short temp = 0;
	temp += buffer[0];
	temp += buffer[1] << 8;
	return temp;
}