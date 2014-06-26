#include <stdlib.h>
#include <string.h>
#include <openssl/rc4.h>

//Complete RC4 encryption (all-in-one)
unsigned char* rc4_crypt(long message_length, unsigned char* message, long key_length, unsigned char* key) {
   RC4_KEY rc4_key;
   RC4_set_key(&rc4_key, key_length, key);
   unsigned char* output = malloc(sizeof(char)*message_length);
   RC4(&rc4_key, (unsigned long)message_length, message, output);
   return output;
}
