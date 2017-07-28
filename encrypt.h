#ifndef ENCRYPT_H_
#define ENCRYPT_H_


#include <stdio.h>    // printf, perror
#include <stdlib.h>   // malloc, rand
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
#endif


#include "aes.h"      // AES-256 encryption
#include "sha256.h"   // SHA-256 hashing

#ifndef CHUNK_SIZE    // Max size of chunk to read at a time
	#define CHUNK_SIZE		2048
#endif
#ifndef PAD_SIZE      // To calculate how much padding to add to data
	#define PAD_SIZE		(BLOCKLEN)
#endif

/* This jst deals with having global variables in an easy way */
#ifndef _VARS
#define _VARS
/** Cross platform path separator **/
const char kPathSeparator =
#ifdef _WIN32
                            '\\';
#else
                            '/';
#endif


static int v_flag = 0, ecb_flag = 0; // Verbose mode
static uint8_t key[32]; // Length of key is 32, because of SHA256. If KEYLEN changes, only first XX bytes will be used.
static uint8_t iv_ptr[BLOCKLEN] = {0}; // Allocate some stack space for our init vector (AES)
#endif // _VARS

int encrypt(const char *fname);
int decrypt(const char *fname);
void traverse(const char *dir, int e_flag);
int is_dir(const char *path);
int is_file(const char *path);
void gen_iv(uint8_t *ptr);
void setKey(const char *k, int len);
void v_print(int v, const char* format, ...);

#endif
