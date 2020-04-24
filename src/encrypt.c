#include "encrypt.h"

#ifdef _WIN32
#include <windows.h>

/**
 * Prints a prompt and retrieves password from keyboard input. The console 
 * will be 'muted' so the password does not appear onscreen.
 *
 * @param prompt The prompt string to print
 * @param buf The buffer to read the password into
 * @param len The maximum number of bytes to read into buf
 */
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

/**
 * Prints a given prompt and gets password from keyboard input. The console 
 * will be 'muted' so the password does not appear onscreen.
 *
 * @param prompt The prompt string to print
 * @param buf The buffer to read the password into
 * @param len The maximum number of bytes to read into buf
 */
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

/**
 * Generates a array of cryptographically secure pseudorandom numbers. This uses getrandom() 
 * on *nix systems and CryptGenRandom on Windows. 
 *
 * @param buf The buffer to store the random numbers in
 * @param bytes The number of bytes of randoms to generate
 * @return 0 on success, nonzero on error
 */
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

int v_flag = 0; // Verbose mode
int keysize = 128; // Default keysize
uint8_t key[32]; // Length of key is 32, because of SHA256. If KEYLEN changes, only first XX bytes will be used.
uint8_t iv_ptr[BLOCKLEN] = {0}; // Allocate some stack space for our init vector (AES)


/** 
 * Reads a line and trims trailing whitespace, excluding spaces 
 *
 * @param line The buffer to read the line into
 * @param max_bytes The maximum number of bytes to read
 * @param stream The file stream to read from
 * @return The number of bytes read into line
 */
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

/** 
 * Checks if a given path is a file 
 *
 * @param path The path to test for file-ness
 * @return nonzero if path is a file, 0 otherwise 
 */
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

/** 
 * Checks if a given path is a directory
 * 
 * @param path The path totest for directory-ness
 * @return nonzero if path is a directory, 0 otherwise 
 */
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

/** 
 * Traverses the directory recursively, encrypting or decrypting each file it passes over 
 *
 * @param path The current path to traverse
 * @param e_flag Whether to encrypt(1) or decrypt(0) the files found
 */
void traverse(const char *path, int e_flag) {
	v_print(2, "Traversing directory \"%s\"\n", path);
	char buf[1024] = {0};
	DIR *dir;
	struct dirent *ent;
	
	if((dir = opendir(path)) != NULL) {
		/* print all the files and directories within directory */
		while((ent = readdir (dir)) != NULL) {
#ifdef _WIN32
			GetFullPathName(path, 1024, buf, NULL);
			sprintf(buf, "%s%c%s", buf, kPathSeparator, ent->d_name);
#else
			realpath(path, buf);
			sprintf(buf, "%s%c%s", buf, kPathSeparator, ent->d_name);
#endif
	
			if(is_file(buf)) { // Check if file
				v_print(3, "%s is a file. Working...\n", buf);
				
				if(e_flag)
					encrypt(buf);
				else
					decrypt(buf);
			}
			else if(is_dir(buf)) { // Check if directory
				// Check directory is not ./ or ../
				if(strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
					v_print(3, "%s is a directory. Traversing...\n", buf);
					traverse(buf, e_flag); // Go a level deeper
				}
			}
		}
		closedir(dir);
	} else {
		// Could not open directory
		perror("Error");
	}
}

/**  
 * Resulting output file will be in the format:
 *
 *  <Size of chunk> <CHUNK...>
 *  <Size of chunk> <CHUNK...>
 *  <Size of chunk> <CHUNK...>
 *  <EOF>
 * Where the size of the chunk is a uint32_t (4 byte unsigned int)
 * and the chunk is an array of type uint8_t*
 *
 * @param fname the name of the file to encrypt
 * @return 0 on success, nonzero on failure
 */
int encrypt(const char *fname) {
	v_print(1, "Encrypting file \"%s\"\n", fname);
	FILE *fv = fopen(fname, "rb+");
	if(fv == NULL) {
		v_print(1, "Error opening file.\n");
		return -1;
	}

	char buf[32] = {0};
	char checksum[32] = {0};
	int i = 1;

	v_print(3, "Allocating %d bytes for AES...\n", CHUNK_SIZE*2);
	uint8_t *output = malloc(CHUNK_SIZE); // Allocate chunk of memory for output
	uint8_t *input = malloc(CHUNK_SIZE);  // Allocate chunk of memory for input
	if(output == NULL || input == NULL) {
		output = (output) ? output : input; // Get the successful alloc (if there is one)
		if(output != NULL) free(output); // If one alloc worked and the other failed, free the successful one
		printf("Error allocating memory. Aborting...\n");
		exit(1);
	}

	v_print(2, "Creating temp file...\n");	
	// Get unused name for file
	sprintf(buf, "temp-%d.temp", i);
	while(access(buf, F_OK) != -1) {
		sprintf(buf, "temp-%d.temp", ++i);
	}

	FILE *fv_out = fopen(buf, "wb");
	if(fv_out == NULL) {
		v_print(1, "Internal file error.\n");
		return -1;
	}

	// Generate and write checksum to beginning of file
	sha256((char*)key, checksum, KEYLEN);
	if(fwrite(checksum, 1, 32, fv_out) != 32) {
		printf("Error writing to file. Aborting...\n");
		fclose(fv_out);
		remove(buf);
		exit(1);
	}

	v_print(2, "Reading %s...\n", fname);
	uint32_t len, err, pad, rtotal = 0, wtotal = 0;
	Iv = iv_ptr;
	while( (len = fread(input, 1, CHUNK_SIZE, fv)) ) {
		pad = (BLOCKLEN - (len % BLOCKLEN)) % BLOCKLEN;
		if(pad > 0) {
			// Put some zeroes into buffer for padding
			memset(input + len, 0, pad);
		}
		// Encrypt the buffer
		AES_CBC_encrypt_buffer(output, input, len+pad, key, 0);
		
		// Write size of data
		fwrite(&len, sizeof len, 1, fv_out);
		// Write actual data with padding
		fwrite(output, 1, len+pad, fv_out);
		rtotal += len;
		wtotal += len + pad + sizeof len;
	}
	v_print(2, "Read %d bytes as %d chunks. Wrote %d bytes.\n", rtotal, (rtotal / CHUNK_SIZE)+1, wtotal);
	
	// Cleanup resources
	v_print(3, "Closing \"%s\"...\n", fname);
	fclose(fv);
	v_print(3, "Closing \"%s\"...\n", buf);
	fclose(fv_out);
	v_print(3, "Freeing AES memory...\n");
	free(input);
	free(output);
	
	v_print(2, "Moving \"%s\" to \"%s\"...\n", buf, fname);
	
	// Rename temp file to main file
	remove(fname); // Remove old file
	if( (err = rename(buf, fname)) != 0) {
		printf("Error moving file.\n");
		if(err == 4) { // If complete failure, delete the temp file
			// Otherwise leave it in case data needs to be recovered somehow
			v_print(2, "Removing temp file...\n");
			remove(buf);
		}
		return -1;
	}
	
	v_print(1, "Done working on \"%s\"\n\n", fname);
	
	return 0;
}

/**
 * Accepts a file that was encrypted using encrypt()
 * Decrypts the file and keeps the original file name
 * 
 * @param fname The name of the file to decrypt
 * @return 0 on success, nonzero on failure
 */
int decrypt(const char *fname) {
	v_print(1, "Decrypting file \"%s\"\n", fname);
	FILE *fv = fopen(fname, "rb");
	if(fv == NULL) {
		v_print(1, "Error opening file.\n");
		return -1;
	}
	
	char buf[32] = {0};
	char checksum[32], checkcheck[32];
	int i = 1;
	
	v_print(3, "Allocating %d bytes for AES...\n", CHUNK_SIZE*2);
	uint8_t *output = malloc(CHUNK_SIZE); // Allocate chunk of memory for output
	uint8_t *input = malloc(CHUNK_SIZE);  // Allocate chunk of memory for input
	if(output == NULL || input == NULL) {
		printf("Error allocating memory. Aborting...\n");
		exit(1);
	}
	
	// Generate and write checksum to beginning of file
	sha256((char*)key, checkcheck, KEYLEN);
	fread(checksum, 1, 32, fv);
	
	if(memcmp(checkcheck, checksum, 32) != 0) {
		printf("Invalid checksum, quitting.\n");
		free(output);
		free(input);
		exit(1);
	}
	
	v_print(2, "Creating temp file...\n");

	// Get unused name for file
	sprintf(buf, "temp-%d.temp", i);
	while(access(buf, F_OK) != -1) {
		sprintf(buf, "temp-%d.temp", ++i);
	}
	
	FILE *fv_out = fopen(buf, "wb");
	if(fv_out == NULL) {
		v_print(1, "Error opening temp file '%s'.\n", buf);
		return -1;
	}
	
	v_print(2, "Reading %s...\n", fname);
	
	uint32_t len, err, pad, rtotal = 0, wtotal = 0;
	Iv = iv_ptr; // Set iv initially, AES_CBC_decrypt_buffer will update as necessary
	// Read size of data in loop
	while( fread(&len, sizeof len, 1, fv) ) {
		pad = (BLOCKLEN - (len % BLOCKLEN)) % BLOCKLEN; // Get size of padding
		// Read correct number of bytes into buffer
		err = fread(input, 1, len+pad, fv);
		if(err != len+pad) {
			printf("Error: File read issue.\n");
			return -1;
		}
		// Decrypt the data
		AES_CBC_decrypt_buffer(output, input, len+pad, key, 0);
		// Write only the data to output (not zero padding)
		fwrite(output, 1, len, fv_out);
		rtotal += len + pad + sizeof len;
		wtotal += len;
	}
	v_print(2, "Read %d bytes as %d chunks. Wrote %d bytes.\n", rtotal, (rtotal / CHUNK_SIZE)+1, wtotal);
	
	// Cleanup resources
	v_print(3, "Closing \"%s\"...\n", fname);
	fclose(fv);

	v_print(3, "Closing \"%s\"...\n", buf);
	fclose(fv_out);

	v_print(3, "Freeing AES memory...\n");
	free(output);
	free(input);
	
	v_print(2, "Moving \"%s\" to \"%s\"...\n", buf, fname);
	
	// Rename temp file to main file
	remove(fname); // Remove old file
	if( (err = rename(buf, fname)) != 0) {
		printf("Error moving file.\n");
		if(err == 4) { // If complete failure, delete the temp file 
			v_print(2, "Removing temp file...\n");
			remove(buf);
		}
		return -1;
	}
	v_print(1, "Done working on \"%s\"\n\n", fname);

	return 0;
}

/** 
 * Print a verbose message where v is the verbosity rank 
 * e.g. if the call is v_print(2, "some message") then the program 
 * needs to be run with at least 2 v flags (-vv) to print the message
 * 
 * @param v The level of verbosity to display this message at
 * @param format The format string
 * @param ... A list of arguments corresponding to the format string
 */
void v_print(int v, const char* format, ...) {
    va_list argptr;
    va_start(argptr, format);
    if(v_flag >= v)
		vprintf(format, argptr);
    va_end(argptr);
}

