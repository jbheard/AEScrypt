#ifndef _SCRYPT_H_
#define _SCRYPT_H_

/**
 * Scrypt functions for password based key derivation
 * Functions here are based off of RFC 2104, 2898, 7914
 * and tested using the test vectors outlined in RFC7914
 *
 * @author Jacob Heard
 */
#include <stdint.h>

struct ScryptInfo {
	uint8_t *salt;  // salt to use
	uint32_t slen;  // salt length (in bytes

	// Note: n must be a power of 2 < 2^(128*r/8)
	int32_t n, p;   // CPU/memory cost, parallelization parameter

	uint32_t dklen; // Derived key length (in bytes)
	int32_t r;      // blocksize
};

/**
 * Initializes values of a ScryptInfo struct to their defaults.
 * The user can then make any desire changes to the values.
 *
 * @param info A pointer to the ScryptInfo struct to fill
 */
void initScryptInfo(struct ScryptInfo *info);

/**
 * Based on RFC 7914 and the "Stronger Key Derivation 
 * via Sequential 
 * Memory-Hard Functions" (http://www.tarsnap.com/scrypt/scrypt.pdf)
 * 
 * @param passwd The \0 terminated password
 * @param info A struct with parameters for scrypt to use.
 *        Leave NULL for defaults.
 * 
 * @return A derived key of length dklen bytes
 */
uint8_t *scrypt(char *passwd, int plen, struct ScryptInfo *info);

/**
 * Based on RTF2104 HMAC specification + wikipedia pseudocode
 * 
 * @param key The key to use for the hash function
 * @param klen Length of key in bytes
 * @param message The message to be HMACd
 * @param mlen Length of the message in bytes
 *
 * @return The HMAC of the message using key (allocated using malloc, must be freed by user)
 */
void HMAC_SHA256(const uint8_t *key, int klen, const uint8_t*message, int mlen, uint8_t *out);

/**
 * Extracts, and extends entropy from a given password into
 * a key of desired size. Based on RTF2898 PBKDF2 (section 5.2)
 *
 * @param passwd The \0 terminated password to use
 * @param salt The random salt to use
 * @param slen The length of the salt (in bytes)
 * @param c The number of rounds
 * @param dklen The desired key length of the result
 * 
 * @return A pointer to a key of length dklen, the key 
 * is created using malloc and should be freed by the user
 */
uint8_t *PBKDF2(const uint8_t *passwd, int plen, const uint8_t *salt, int slen, int c, int dklen);

#endif // _SCRYPT_H_
