/** AES encryption software
  *    @author Jacob Heard
  * 
  * Command line program to encrypt a file or directory using AES. 
  * Accepts key as text input or a file. If given a password as key, 
  * will create a key file.
  * DO NOT LOSE THE FILE. The key file cannot be recreated from the password. 
  * If you would like to use a password use the option -s for simple mode (ECB)
  * This will use a less secure version of AES, but the key file can be recreated 
  * from a password.
  **/


#include "encrypt.h"


int main(int argc, char **argv) {
	if(argc < 2) {
		printf("Usage: %s path [-r -ed] [-k key] [-f keyfile]\nUse %s --help to show help page.\n", argv[0], argv[0]);
		return 0;
	}
	/* Display help page */
	if(strcmp(argv[1], "--help") == 0) {
		printf("Usage: %s path [-r -ed] [-k key] [-f keyfile] [-s]\n", argv[0]);
		printf("  Encrypts a file or directory using AES. Applies a given key or generates one randomly into a file.\n\n");
		printf("  path    The file/path to work on\n");
		printf("  -r      Recursively search files\n");
		printf("  -e      Sets mode to encrypt given file/directory\n");
		printf("  -d      Sets mode to decrypt given file/directory\n");
		printf("  -k      Sets seed for key to \"key\"\n");
		printf("  -f      Sets key to the contents of \"keyfile\"\n");
		printf("  -s      Uses ECB over CBC version of AES. Less secure, but the key file can be recreated.\n");
		printf("  -v(vv)  Verbose mode. Use more/less Vs depending on how verbose you want it.\n");
		printf("\n");
		return 0;
	}
	
	/* This shouldn't happen, but idk. Maybe someone on *nux will try to encrypt a pipe or something */
	if(!is_file(argv[1]) && !is_dir(argv[1])) {
		printf("Error: Could not find \"%s\", please check that it is a file or directory and there are no typos.\n", argv[1]);
		return 1;
	}

	const char *path = argv[1]; // Descriptive alias for argv[1]
	gen_iv(iv_ptr); // Generate an init vector
	Iv = iv_ptr; // Set internal iv pointer to our own
	
	int e_flag = 1, r_flag = 0, key_flag = 0;
	int c;
	FILE *fv = NULL;
	while((c = getopt (argc, argv, "vsredf:k:")) != -1) {
		switch(c) {
			case 's':
				ecb_flag = 1;
				break;
			case 'v':
				v_flag += 1;
				break;
			case 'r':
				r_flag = 1;
				break;
			case 'e':
				e_flag = 1;
				break;
			case 'd':
				e_flag = 0;
				break;
			case 'k':
				setKey(optarg, strlen(optarg));
				key_flag = 1;
				break;
			case 'f':
				fv = fopen(optarg, "rb");
				if(fv == NULL) {
					printf("Error opening key file.\n");
					return -1;
				}
				v_print(1, "Reading key from file.\n");
				fread(&ecb_flag, sizeof ecb_flag, 1, fv);
				fread(key, 1, 32, fv);
				if(!ecb_flag)
					fread(Iv, 1, 32, fv);
				fclose(fv);
				key_flag = 2;
				break;
			case '?':
				if(optopt == 'f' || optopt == 'k')
					printf("Option '-%c' requires an argument.\n", optopt);
				else
					printf("Unknown option: '-%c'\n", optopt);
				return 1;
				break;
			default:
				printf("An unknown error has ocurred.\n");
				return 1;
				break;
		}
	}
	
	// If the user does not provide a key to decrypt, use default
	if(!key_flag && e_flag == 0) {
		printf("Please specify a key file to use for decrypting.\n");
		return 1;
	} else if(!key_flag && ecb_flag) {
		/* Quick note about this, the only reason a user should use ECB mode is for a re-usable key. 
		 * This is more like a password that they can use rather than having to keep a file somewhere.
		 * ECB is conderably less secure than CBC mode, so if the user does not intend to remember a 
		 * password anyway, it is much more effective to use CBC AES.
		 */
		printf("To use ECB mode, you need to enter a key or key file.\nFor a randomly generated key, use the more secure CBC mode.\n");
		return 1;
	}

	// If the user did not specify a key file, create one
	if(key_flag != 2) {
		v_print(1, "Creating key file...\n");
		char buf[20] = {0};
		int i = 1;
		
		// Create random seed for key
		if(!key_flag) {
			srand(time(0));
			char tmp_key[32] = {0};
			for(int i = 0; i < 32; i++)
				tmp_key[i] = rand() % 0xFF;
			setKey(tmp_key, 11);
		}
		
		// Get unused name for file
		sprintf(buf, "key-%d.aes", i);
		while(access(buf, F_OK) != -1) {
			sprintf(buf, "key-%d.aes", ++i);
		}
		
		// Create file and write key+iv
		fv = fopen(buf, "wb");
		if(fv == NULL) {
			printf("Error: Could not create key file. Aborting...\n");
			return 1;
		}
		fwrite(&ecb_flag, sizeof ecb_flag, 1, fv); // Write mode
		fwrite(key, 1, 32, fv);
		if(!ecb_flag)
			fwrite(iv_ptr, 1, 32, fv);
		fclose(fv);
		
		printf("Created key file \"%s\"\n", buf); // Let user know name of key file
	}
	
	if(!r_flag && !is_file(path)) {
		printf("Error: \"%s\" could not be found.\n", path);
		return 1;
	}
	if(r_flag) // Recursively find and encrypt/decrypt files
		traverse(path, e_flag);
	else if(is_file(path)) { // Make sure we are working with a file
		if(e_flag)
			encrypt(path);
		else
			decrypt(path);
	} else {
		printf("Error: \"%s\" does not seem to be a file. Please check and try again.\n", path);
		return 1;
	}
	
	return 0;
}


// Sets AES256 key to the SHA256 hash of some data
void setKey(const char *k, int len) {
	v_print(2, "Creating and setting key.\n");
	SHA256_CTX ctx; // Create CTX object on stack
	sha256_init(&ctx); // Init CTX object
	sha256_update(&ctx, (uint8_t*)k, len); // Add key data to CTX
	sha256_final(&ctx, key); // Get SHA256 hash for key
}

// Generates a random initialization vector for AES256
void gen_iv(uint8_t *ptr) {
	v_print(2, "Generating AES initialization vector.\n");
	srand(time(0));
	for(int i = 0; i < BLOCKLEN; i++) {
		ptr[i] = rand() % 256;
	}
}

// Returns 0 if path is not a file, nonzero otherwise
int is_file(const char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
//	return !is_dir(path);
}

// Returns 0 if path is not a directory, nonzero otherwise
int is_dir(const char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
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
