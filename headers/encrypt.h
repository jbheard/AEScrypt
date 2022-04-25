#ifndef ENCRYPT_H_
#define ENCRYPT_H_


#include <stdio.h>    // printf, perror
#include <stdlib.h>   // malloc
#include <limits.h>   // realpath
#include <time.h>     // time
#include <string.h>   // memset

#include <stdint.h>   // uint32_t, uint8_t
#include <getopt.h>   // getopt

#include <sys/stat.h> // lstat, S_ISDIR, S_ISREG
#include <unistd.h>   // access
#include <dirent.h>   // opendir, readdir

#ifdef _WIN32
	#include <windows.h>  // GetFullPathName
	#include <wincrypt.h> // CryptGenRandom
#else
	#include <sys/random.h>
#endif


#include "aes.h"      // AES-256 encryption
#include "sha256.h"   // SHA-256 hashing
#include "cryptstructs.h"


void decryptFile(const char *path, struct CryptSecrets secrets);
void encryptFile(const char *path, struct CryptSecrets secrets);

#endif
