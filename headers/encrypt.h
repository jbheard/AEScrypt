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


struct CryptOptions {
	int e_flag; // 0 for decrypt, non-0 for encrypt
	int v_flag; // How verbose to be
	int r_flag; // non-zero for recursive (directories)
	int g_flag; // Generate key file
	int mode;   // Which aes mode to use (128, 192, 256)
	int key_flag; // Type of key to use (password or file)
	char kfname[256]; // Path to key file
} options;

struct CryptConfig {
	uint8_t key[32];
	uint8_t iv[BLOCKLEN];
	uint8_t salt[32]; // only used for password mode
};

int getpass(const char *prompt, char *buf, int len);
int gen_randoms(char *buf, int bytes);
int encrypt(const char *fname, struct CryptConfig config);
int decrypt(const char *fname, struct CryptConfig config);
void traverse(const char *dir, int e_flag, struct CryptConfig config);
int is_dir(const char *path);
int is_file(const char *path);
int gen_iv(uint8_t *ptr);
void v_print(int v, const char* format, ...);
size_t readline(char *line, int max_bytes, FILE *stream);

#endif
