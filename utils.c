#include <stdlib.h>

char*          reverse_endian (long length, char* buffer);
unsigned char* ltoc           (long num);
long           ctol           (unsigned char* buffer);
unsigned char* stoc           (short num);
short          ctos           (unsigned char* buffer);

char*
reverse_endian (long length, char* buffer)
{
	char* temp = malloc(sizeof(char) * length);
	int h = 0;
	for (int i = length; i > 0; i--)
	{
		temp[h] = buffer[i];
		h++;
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