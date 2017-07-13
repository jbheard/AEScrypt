#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>


// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// ECB enables the basic ECB 16-byte block algorithm. Both can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

//#define AES128 1
//#define AES192 1
#define AES256 1

#if defined(ECB) && (ECB == 1)

void AES_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);
void AES_ECB_decrypt(const uint8_t* input, const uint8_t* key, uint8_t *output, const uint32_t length);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)

void AES_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

#endif // #if defined(CBC) && (CBC == 1)


/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define KEYLEN 32
    #define Nr 14
    #define keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define KEYLEN 24
    #define Nr 12
    #define keyExpSize 208
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define KEYLEN 16   // Key length in bytes
    #define Nr 10       // The number of rounds in AES Cipher.
    #define keyExpSize 176
#endif

#if defined(CBC) && CBC
  // Initial Vector used only for CBC mode
  extern uint8_t* Iv;
#endif


#endif //_AES_H_
