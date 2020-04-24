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

#ifndef CHUNK_SIZE    // Max size of chunk to read at a time
	#define CHUNK_SIZE		2048
#endif

/** Cross platform path separator **/
static const char kPathSeparator =
#ifdef _WIN32
                                   '\\';
#else
                                   '/';
#endif


extern int v_flag, ecb_flag; // Verbose mode
extern uint8_t key[32]; // Length of key is 32, because of SHA256. If KEYLEN changes, only first XX bytes will be used.
extern uint8_t iv_ptr[BLOCKLEN]; // Allocate some stack space for our init vector (AES)

int getpass(const char *prompt, char *buf, int len);
int gen_randoms(char *buf, int bytes);
int encrypt(const char *fname);
int decrypt(const char *fname);
void traverse(const char *dir, int e_flag);
int is_dir(const char *path);
int is_file(const char *path);
int gen_iv(uint8_t *ptr);
void v_print(int v, const char* format, ...);
size_t readline(char *line, int max_bytes, FILE *stream);

#endif
