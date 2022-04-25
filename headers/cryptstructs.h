#ifndef _CRYPTSTRUCTS_H_
#define _CRYPTSTRUCTS_H_

#include "aes.h"      // AES_BLOCKLEN

#include <stdint.h>

#ifndef CHUNK_SIZE    // Max size of chunk to read at a time
	#define CHUNK_SIZE		8192
#endif

/** Cross platform path separator **/
static const char kPathSeparator =
#ifdef _WIN32
                                   '\\';
#else
                                   '/';
#endif

#define MAX_KEY_SIZE         32
#define SALT_LEN             32
#define CHECKSUM_SIZE        32
#define CRYPT_CONFIG_PV1     1
#define CRYPT_CONFIG_KV1     2
#define CRYPT_HEADER_VERSION 1

struct CryptOptions {
	int e_flag; // 0 for decrypt, non-0 for encrypt
	int v_flag; // How verbose to be
	int r_flag; // non-zero for recursive (directories)
	int g_flag; // Generate key file
	int mode;   // Which aes mode to use (128, 192, 256)
	int key_flag; // Type of key to use (password or file)
	char keyFilePath[256]; // Path to key file
} options;

struct CryptConfig {
	uint32_t version;
	uint8_t iv[AES_BLOCKLEN];
	uint8_t salt[SALT_LEN]; // only used for password mode
};

struct CryptSecrets {
	char* password;
	uint8_t key[MAX_KEY_SIZE];
};

#endif // _CRYPTSTRUCTS_H_

