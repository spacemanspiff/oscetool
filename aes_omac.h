// I mean if OpenSSL doesn't include it...
//  released under GPLv3, see http://gplv3.fsf.org/
#ifndef __AES_OMAC_H_
#define __AES_OMAC_H_

#ifdef __cplusplus
extern "C" {
#endif

void aesOmac1Mode(uint8_t *output, uint8_t *input, int len, uint8_t *aes_key_data, int aes_key_bits);

#ifdef __cplusplus
}
#endif

#endif
