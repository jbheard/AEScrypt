#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#ifdef _WIN32
	#include <windows.h>
	#include <wincrypt.h> // CryptGenRandom
#else
	#include <sys/random.h>
#endif

#include "cryptstructs.h"
#include "filequeue.h"

#define PASSWORD_MODE  1
#define FILE_MODE      2
#define MAX_PASSWORD_LENGTH 128

void writeKeyFile(struct CryptSecrets* secrets);
void readKeyFile(struct CryptSecrets* secrets);
void getPassword(char *passwd);
void getConfigFromPassword(struct CryptConfig* config, struct CryptSecrets* secrets);
FILE *getTempFile(char* nameBuffer);
int replace(const char* src, const char* dst);
void doAllFiles(struct PathNode* start, struct CryptSecrets secrets);

/**
 * Generates a array of cryptographically secure pseudorandom numbers. This uses getrandom() 
 * on *nix systems and CryptGenRandom on Windows. 
 *
 * @param buf The buffer to store the random numbers in
 * @param bytes The number of bytes of randoms to generate
 * @return 0 on success, nonzero on error
 */
int gen_randoms(char *buf, int bytes);

/** 
 * Checks if a given path is a file 
 *
 * @param path The path to test for file-ness
 * @return nonzero if path is a file, 0 otherwise 
 */
int is_file(const char* path);

/** 
 * Checks if a given path is a directory
 * 
 * @param path The path totest for directory-ness
 * @return nonzero if path is a directory, 0 otherwise 
 */
int is_dir(const char* path);

/** 
 * Print a verbose message where v is the verbosity rank 
 * e.g. if the call is v_print(2, "some message") then the program 
 * needs to be run with at least 2 v flags (-vv) to print the message
 * 
 * @param v The level of verbosity to display this message at
 * @param format The format string
 * @param ... A list of arguments corresponding to the format string
 */
void v_print(int v, const char* format, ...);

/** 
 * Reads a line and trims trailing whitespace, excluding spaces 
 *
 * @param line The buffer to read the line into
 * @param max_bytes The maximum number of bytes to read
 * @param stream The file stream to read from
 * @return The number of bytes read into line
 */
size_t readline(char* line, int max_bytes, FILE* stream);

#endif // UTILS_H_
