#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h> // lstat, S_ISDIR, S_ISREG
#include <unistd.h>   // access

#include "encrypt.h"
#include "cryptstructs.h"
#include "scrypt.h"
#include "utils.h"


int is_file(const char *path) {
    struct stat path_stat;
#ifdef _WIN32
	/** TODO Check for symlinks on windows? **/
    stat(path, &path_stat);
#else
	// Handles symlinks on *nix machines
	lstat(path, &path_stat);
#endif
    return S_ISREG(path_stat.st_mode);
}

int is_dir(const char *path) {
    struct stat path_stat;
#ifdef _WIN32
	/** TODO Check for symlinks on windows? **/
    stat(path, &path_stat);
#else
	// Handles symlinks on *nix machines
	lstat(path, &path_stat);
#endif
    return S_ISDIR(path_stat.st_mode);
}

void v_print(int v, const char* format, ...) {
    va_list argptr;
    va_start(argptr, format);
    if(options.v_flag >= v)
		vprintf(format, argptr);
    va_end(argptr);
}

size_t readline(char *line, int max_bytes, FILE *stream) {
	fgets(line, max_bytes, stream);
	size_t len = strlen(line);
	int whitespace = 1; // loop condition, there is still whitespace
	while(whitespace) {
		switch(line[len-1]) {
		case '\n': case '\r':
		case '\f': case '\t':
			line[len-1] = '\0';
			len--;
			break;
		default:
			whitespace = 0;
			break;
		}
	}
	return len;
}

int gen_randoms(char *buf, int bytes) {
#ifdef _WIN32
	HCRYPTPROV hCryptProv = 0; // Crypto context
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) == 0) {
		return 1;
	}
	if(CryptGenRandom(hCryptProv, bytes, (PBYTE)buf) == 0) { // Generate random number
		return 1;
	}
#else
	//TODO verify this works on older *nix distros, or find workaround
	if(getrandom(buf, bytes, GRND_NONBLOCK) == -1) {
		return 1;
	}
#endif
	return 0;
}

#ifdef _WIN32
#include <windows.h>

int getpass(const char *prompt, char *buf, int len) {
	DWORD oflags;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);

	// Get initial console mode
	if(!GetConsoleMode(h, &oflags)) {
		perror("retrieving console mode");
		return -1;
	}
	// Disable echo on input
	if(!SetConsoleMode(h, oflags & (~ENABLE_ECHO_INPUT))){
		perror("disabling output");
		return -1;
	}

	// Read the actual password
    printf("%s", prompt); // Print prompt
    len = readline(buf, len, stdin); // Get password & length
	
	// Restore console state
	if(!SetConsoleMode(h, oflags)) {
		perror("restoring console");
		return -1;
	}
	printf("\n");
	return len;
}

#else
#include <termios.h>

int getpass(const char *prompt, char *buf, int len) {
    struct termios oflags, nflags;
	
    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        perror("tcsetattr failed to disable echo");
        return -1;
    }

    printf("%s", prompt); // Print prompt
    len = readline(buf, len, stdin); // Get line
	
    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        perror("tcsetattr failed to restore terminal");
        return -1;
    }
	printf("\n");
	return len;
}

#endif

void getPassword(char *passwd) {
	static char firstTry[MAX_PASSWORD_LENGTH] = {0};
	// Password mode; get password, set IV and key based on user input
	int len = getpass("password: ", firstTry, MAX_PASSWORD_LENGTH);
	if(options.e_flag) {
		char secondTry[MAX_PASSWORD_LENGTH] = {0};
		getpass("repeat  : ", secondTry, MAX_PASSWORD_LENGTH);
		if(strcmp(firstTry, secondTry) != 0) {
			printf("Passwords do not match, aborting...\n");
			exit(EXIT_FAILURE);
		}
	}
	strncpy(passwd, firstTry, MAX_PASSWORD_LENGTH);
}

void readKeyFile(struct CryptSecrets* secrets) {
	// A key file was specified for encryption
	// Open the file and read the key
	FILE *fv = fopen(options.keyFilePath, "rb");
	if(fv == NULL) {
		printf("Error opening key file \"%s\".\n", options.keyFilePath);
		exit(EXIT_FAILURE);
	}
	uint16_t kl;
	v_print(1, "Reading key from file.\n");
	fread(&kl, sizeof kl, 1, fv); // Get key size
	int read = fread(secrets->key, 1, kl, fv); // Read key
	fclose(fv); // Close file
	
	if(read != kl) {
		exit(EXIT_FAILURE);
	}
	
	// In case we are in the wrong mode
	if(kl != KEYLEN) {
		printf("Inconsistent mode, changing to %d bit mode\n", kl*8);
		setAESMode(kl*8);
	}
}

void writeKeyFile(struct CryptSecrets* secrets) {
	v_print(1, "Creating key file...\n");
	
	// If the key file name was not specified
	if(options.keyFilePath[0] == '\0') {
		int i = 1;
		// Get unused name for file
		sprintf(options.keyFilePath, "key-%d.aes", i);
		while(access(options.keyFilePath, F_OK) != -1) {
			sprintf(options.keyFilePath, "key-%d.aes", ++i);
		}
	}
	
	// Create file and write key
	FILE *fv = fopen(options.keyFilePath, "wb");
	if(fv == NULL) {
		printf("Error: Could not create key file. Aborting...\n");
		exit(EXIT_FAILURE);
	}
	uint16_t kl = (uint16_t)KEYLEN;
	fwrite(&kl, sizeof kl, 1, fv); // Write key size
	int wrote = fwrite(secrets->key, 1, KEYLEN, fv); // Write key
	fclose(fv); // Close file
	
	if(wrote != kl) {
		exit(EXIT_FAILURE);
	}
	
	printf("Created key file \"%s\"\n", options.keyFilePath); // Let user know name of key file
}

FILE *getTempFile(char* nameBuffer) {
	int i = 1;
	
	// Get unused name for file
	sprintf(nameBuffer, "temp-%d.temp", i);
	while(access(nameBuffer, F_OK) != -1) {
		sprintf(nameBuffer, "temp-%d.temp", ++i);
	}

	FILE *fv = fopen(nameBuffer, "wb");
	if(fv == NULL) {
		v_print(3, "Error creating temp file \"%s\".\n", nameBuffer);
		return NULL;
	}
	return fv;
}

void getConfigFromPassword(struct CryptConfig* config, struct CryptSecrets* secrets) {
	// Scrypt variables
	struct ScryptInfo info;
	uint8_t *ptr;

	initScryptInfo(&info);
	info.salt = config->salt;
	info.slen = SALT_LEN;
	info.dklen = (AES_BLOCKLEN + MAX_KEY_SIZE)*2;

	// Run scrypt
	ptr = scrypt(secrets->password, strlen(secrets->password), &info);

	// Use scrypt result for key and IV
	memcpy(secrets->key, ptr, MAX_KEY_SIZE);
	memcpy(config->iv, ptr + MAX_KEY_SIZE, AES_BLOCKLEN);
	free(ptr); // Clean up
}

int replace(const char* src, const char* dst) {
	int err;
	remove(dst); // Remove old file
	if( (err = rename(src, dst)) != 0) {
		printf("Error moving file \"%s\" to \"%s\".\n", src, dst);
		v_print(2, "Removing temp file...\n");
		remove(src);
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}

void doAllFiles(
	struct PathNode* start,
	struct CryptSecrets secrets
) {
	char path[PATH_MAX_LENGTH+1] = {0};
	int encrypt = options.e_flag;
	
	while(start) {
		start = getNextPath(start, path);
		if(encrypt) {
			encryptFile(path, secrets);
		} else {
			decryptFile(path, secrets);
		}
	}
}

