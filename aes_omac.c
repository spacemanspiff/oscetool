// I mean if OpenSSL doesn't include it...
//  released under GPLv3, see http://gplv3.fsf.org/

#include "types.h"
#include "polarssl/aes.h"

static void rol1(uint8_t * worthless) {
  int i;
  uint8_t xor = (worthless[0]&0x80)?0x87:0;
  for(i=0;i<0xF;i++) {
    worthless[i] <<= 1;
    worthless[i] |= worthless[i+1]>>7;
  }
  worthless[0xF] <<= 1;
  worthless[0xF] ^= xor;
}

void aesOmac1Mode(uint8_t * output, uint8_t * input, int len, uint8_t * aes_key_data, int aes_key_bits) {
  int i = 0;
  int j;
  aes_context aes_ctx;
  aes_setkey_enc(&aes_ctx, aes_key_data, aes_key_bits);

  uint8_t running[0x10]; memset(running, 0, 0x10);
  uint8_t hash[0x10];
  uint8_t worthless[0x10];
  //uint8_t final[0x10];

  aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, running, worthless);
  rol1(worthless);

  if(len > 0x10) {
    for(i=0;i<(len-0x10);i+=0x10) {
      for(j=0;j<0x10;j++) hash[j] = running[j] ^ input[i+j];
      aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, hash, running);
    }
  }
  int overrun = len&0xF;
  if( (len%0x10) == 0 ) overrun = 0x10;

  memset(hash, 0, 0x10);
  memcpy(hash, &input[i], overrun);

  if(overrun != 0x10) {
    hash[overrun] = 0x80;
    rol1(worthless);
  }

  for(j=0;j<0x10;j++) hash[j] ^= running[j] ^ worthless[j];
  aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, hash, output);
}
