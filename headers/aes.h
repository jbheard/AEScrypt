#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

void setAESMode(const uint32_t mode);

void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);
void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

extern int KEYLEN;
// Initial Vector used only for CBC mode
extern uint8_t* Iv;

#endif //_AES_H_
