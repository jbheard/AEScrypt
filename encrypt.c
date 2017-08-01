#include "encrypt.h"


int v_flag = 0, ecb_flag = 0; // Verbose mode
uint8_t key[32]; // Length of key is 32, because of SHA256. If KEYLEN changes, only first XX bytes will be used.
uint8_t iv_ptr[BLOCKLEN] = {0}; // Allocate some stack space for our init vector (AES)


/* Sets AES256 key to the SHA256 hash of some data */
void setKey(const char *k, int len) {
	v_print(2, "Creating and setting key.\n");
	SHA256_CTX ctx; // Create CTX object on stack
	sha256_init(&ctx); // Init CTX object
	sha256_update(&ctx, (uint8_t*)k, len); // Add key data to CTX
	sha256_final(&ctx, key); // Get SHA256 hash for key
}

/* Generates a random initialization vector for AES256 */
int gen_iv(uint8_t *ptr) {
	v_print(2, "Generating AES initialization vector.\n");
#ifdef _WIN32
	HCRYPTPROV hCryptProv = 0; // Crypto context
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) == 0)
		return 1;
	if(CryptGenRandom(hCryptProv, BLOCKLEN, ptr) == 0) // Generate random number
		return 1;
#else
	//TODO verify this works on older *nix distros, or find workaround
	if(getrandom(ptr, BLOCKLEN, GRND_NONBLOCK) == -1)
		return 1;
#endif
	return 0;
}

/* Returns 0 if path is not a file, nonzero otherwise */
int is_file(const char *path) {
	// TODO Check for symlinks on windows?
    struct stat path_stat;
#ifdef _WIN32
    stat(path, &path_stat);
#else
	// Handles symlinks on *nix machines
	lstat(path, &path_stat);
#endif
    return S_ISREG(path_stat.st_mode);
}

/* Returns 0 if path is not a directory, nonzero otherwise */
int is_dir(const char *path) {
	// TODO Check for symlinks on windows?
    struct stat path_stat;
#ifdef _WIN32
    stat(path, &path_stat);
#else
	// Handles symlinks on *nix machines
	lstat(path, &path_stat);
#endif
    return S_ISDIR(path_stat.st_mode);
}


/* Traverses the directory recursively, en/decrypting each file it passes over */
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

/*  Resulting output file will be in the format:
 *
 *  <Size of chunk> <CHUNK...>
 *  <Size of chunk> <CHUNK...>
 *  <Size of chunk> <CHUNK...>
 *  <EOF>
 * Where the size of the chunk is a uint32_t (4 byte unsigned int)
 * and the chunk is an array of type *uint8_t
 * Returns 0 on success, nonzero on failure
 */
int encrypt(const char *fname) {
	v_print(1, "Encrypting file \"%s\"\n", fname);
	FILE *fv = fopen(fname, "rb");
	if(fv == NULL) {
		v_print(1, "Error opening file.\n");
		return -1;
	}

	v_print(2, "Creating temp file...\n");
	char buf[32] = {0};
	int i = 1;
	
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

	v_print(3, "Allocating %d bytes for AES...\n", CHUNK_SIZE*2);
	uint8_t *output = malloc(CHUNK_SIZE); // Allocate chunk of memory for output
	uint8_t *input = malloc(CHUNK_SIZE);  // Allocate chunk of memory for input
	if(output == NULL || input == NULL) {
		printf("Error allocating memory. Aborting...\n");
		exit(1);
	}
	
	v_print(2, "Reading %s...\n", fname);
	uint32_t len, err, pad, rtotal = 0, wtotal = 0;
	while( (len = fread(input, 1, CHUNK_SIZE, fv)) ) {
		pad = (BLOCKLEN - (len % BLOCKLEN)) % BLOCKLEN;
		//DEBUG
		Iv = iv_ptr; // This changes every time we do things, need to make sure all is good
		if(pad > 0) {
			// Put some zeroes into buffer for padding
			memset(input + len, 0, pad);
		}
		// Encrypt the buffer
		if(ecb_flag)
			AES_ECB_encrypt(input, key, output, len+pad);
		else
			AES_CBC_encrypt_buffer(output, input, len+pad, key, Iv);
		
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

/* Accepts a file that was encrypted using encrypt()
 * Decrypts the file and keeps the original file name
 * Returns 0 on success, -1 on failure
 */
int decrypt(const char *fname) {
	v_print(1, "Decrypting file \"%s\"\n", fname);
	FILE *fv = fopen(fname, "rb");
	if(fv == NULL) {
		v_print(1, "Error opening file.\n");
		return -1;
	}
	
	v_print(2, "Creating temp file...\n");
	char buf[32] = {0};
	int i = 1;
	
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
	
	v_print(3, "Allocating %d bytes for AES...\n", CHUNK_SIZE*2);
	uint8_t *output = malloc(CHUNK_SIZE); // Allocate chunk of memory for output
	uint8_t *input = malloc(CHUNK_SIZE);  // Allocate chunk of memory for input
	if(output == NULL || input == NULL) {
		printf("Error allocating memory. Aborting...\n");
		exit(1);
	}
	
	v_print(2, "Reading %s...\n", fname);
	
	uint32_t len, err, pad, rtotal = 0, wtotal = 0;
	// Read size of data in loop
	while( fread(&len, sizeof len, 1, fv) ) {
		pad = (BLOCKLEN - (len % BLOCKLEN)) % BLOCKLEN; // Get size of padding
		// DEBUG
		Iv = iv_ptr;
		// Read correct number of bytes into buffer
		err = fread(input, 1, len+pad, fv);
		if(err != len+pad) {
			printf("Error: File read issue.\n");
			return -1;
		}
		// Decrypt the data
		if(ecb_flag)
			AES_ECB_decrypt(input, key, output, len+pad);
		else
			AES_CBC_decrypt_buffer(output, input, len+pad, key, Iv);
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


/* Print a verbose message where v is the verbosity rank 
 * e.g. if the call is v_print(2, "some message") then the program 
 * needs to be run with at least 2 v flags (-vv) to print the message
 */
void v_print(int v, const char* format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    if(v_flag >= v)
		vprintf(format, argptr);
    va_end(argptr);
}
