#include <stdlib.h>
#include <string.h>

//Adapted RC4 implementation by Brad Conte: http://bradconte.com/rc4_c

// Key Scheduling Algorithm 
// Input: state - the state used to generate the keystream
//        key - Key to use to initialize the state 
//        len - length of key in bytes  
void ksa(unsigned char state[], unsigned char key[], int len)
{
   int i,j=0,t;

   for (i=0; i < 256; ++i)
      state[i] = i;
   for (i=0; i < 256; ++i) {
      j = (j + state[i] + key[i % len]) % 256;
      t = state[i];
      state[i] = state[j];
      state[j] = t;
   }
}

// Pseudo-Random Generator Algorithm 
// Input: state - the state used to generate the keystream 
//        out - Must be of at least "len" length
//        len - number of bytes to generate 
void prga(unsigned char state[], unsigned char out[], int len)
{
   int i=0,j=0,x,t;
   unsigned char key;

   for (x=0; x < len; ++x)  {
      i = (i + 1) % 256;
      j = (j + state[i]) % 256;
      t = state[i];
      state[i] = state[j];
      state[j] = t;
      out[x] = state[(state[i] + state[j]) % 256];
   }
}

//XOR encryption (data against key)
char* xor_encrypt(long message_length, char* message, long key_length, char* key)
{
   char* encrypted = malloc(sizeof(char)*message_length);
   int i = 0;
   for (i = 0; i < message_length; i++)
   {
      encrypted[i] = message[i] ^ key[i % key_length];
   }
   return encrypted;
}

//Complete RC4 encryption (all-in-one)
char* rc4_crypt(long message_length, char* message, long key_length, char* key)
{
   char* temp = malloc(sizeof(char)*message_length);
   if (key_length == 0 || message_length == 0 || sizeof(message) == 0 || sizeof(key) == 0)
   {
      memcpy(temp, message, message_length);
      return temp;
   }
   unsigned char state[256];
   ksa(state, key, key_length);
   prga(state, temp, message_length);
   char* encrypted = xor_encrypt(message_length, message, key_length, temp);
   free(temp);
   return encrypted;
}
