#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "encrypt.h"
#include "scrypt.h"
#include "utils.h"

int handleOptions(const char *path) {
	struct CryptConfig config;

	// If the user does not provide a key to decrypt, die
	if(!options.key_flag && !options.e_flag) {
		printf("Please specify a key file or use password for decrypting.\n");
		return EXIT_FAILURE;
	}

	if(options.key_flag == PASSWORD_MODE) {
		GetConfigFromPassword(&config);
	} else if(options.e_flag) { // If we are encrypting and NOT using a password, generate IV randomly
		v_print(2, "Generating AES initialization vector.\n");
		if(gen_randoms((char*)config.iv, AES_BLOCKLEN) != 0) { // Generate an init vector
			printf("Error generating IV\n");
			return EXIT_FAILURE;
		}
	}

	if(options.e_flag && options.kfname[0] != '\0') { 
		int exists = (access(options.kfname, F_OK) == 0);
		if(options.g_flag && exists) {
			char choice[4] = {0};
			printf("The file \"\" will be overwritten, would you like to continue? (Y/N) ");
			fgets(choice, 4, stdin);
			if(choice[0] != 'y' && choice[0] != 'Y') {
				printf("Aborting...\n");
				exit(EXIT_FAILURE);
			}
		} else if( !exists ) {
			// If the file does not exist, set the flag to create it
			options.g_flag = 1;
		}
	}

	DoKeyFile(config);

	if(!options.r_flag && !is_file(path)) {
		printf("Error: \"%s\" could not be found.\n", path);
		return EXIT_FAILURE;
	}

	if(options.r_flag) {
		traverse(path, options.e_flag, config);
	} else if(is_file(path)) {
		if(options.e_flag) {
			encrypt(path, config);
		} else {
			decrypt(path, config);
		}
	} else {
		printf("Error: \"%s\" is not a file\n", path);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void getPassword(char *passwd) {
	static char firstTry[128] = {0};
	// Password mode; get password, set IV and key based on user input
	int len = getpass("password: ", firstTry, 128);
	if(options.e_flag) {
		char secondTry[128] = {0};
		getpass("repeat  : ", secondTry, 128);
		if( strcmp(firstTry, secondTry) != 0 ) {
			printf("Passwords do not match, aborting...\n");
			exit(EXIT_FAILURE);
		}
		strncpy(passwd, firstTry, 128);
	}
}

void GetConfigFromPassword(struct CryptConfig *config) {
	char pass[129] = {0}; // Extra byte in case password is 128 chars long
	v_print(2, "Creating and setting key.\n");

	// Scrypt variables
	struct ScryptInfo info;
	uint8_t *ptr;

	// Set up our parameters
	if( options.e_flag ) {
		gen_randoms((char*)config->salt, SALT_LEN);
	}
	initScryptInfo(&info);
	info.salt = config->salt;
	info.slen = SALT_LEN;
	info.dklen = AES_BLOCKLEN + MAX_KEY_SIZE;
	getPassword(pass);

	// Run scrypt
	ptr = scrypt(pass, strlen(pass), &info);

	// Use scrypt result for key and IV
	memcpy(config->key, ptr, MAX_KEY_SIZE);
	memcpy(config->iv, ptr+MAX_KEY_SIZE, AES_BLOCKLEN);
	free(ptr); // Clean up
}

static void readKey(struct CryptConfig config) {
	// A key file was specified for encryption
	// Open the file and read the key
	FILE *fv = fopen(options.kfname, "rb");
	if(fv == NULL) {
		printf("Error opening key file \"%s\".\n", options.kfname);
		exit(EXIT_FAILURE);
	}
	uint16_t kl;
	v_print(1, "Reading key from file.\n");
	fread(&kl, sizeof kl, 1, fv); // Get key size
	fread(config.key, 1, kl, fv); // Read key
	fread(config.iv, 1, AES_BLOCKLEN, fv); //  Read IV
	fclose(fv); // Close file
	
	// In case we are in the wrong mode
	if(kl != KEYLEN) {
		printf("Inconsistent mode, changing to %d bit mode\n", kl*8);
		setAESMode(kl*8);
	}
}

static void writeKey(struct CryptConfig config) {
	v_print(1, "Creating key file...\n");
	int i = 1;
	
	// Create random seed for key
	if(options.key_flag != PASSWORD_MODE) { // If we didn't already get a password for this
		if(gen_randoms((char*)config.key, KEYLEN) != 0) {
			printf("Error generating entropy for key\n");
			exit(EXIT_FAILURE);
		}
	}
	
	// If the key file name was not specified
	if(options.kfname[0] == '\0') {
		// Get unused name for file
		sprintf(options.kfname, "key-%d.aes", i);
		while(access(options.kfname, F_OK) != -1) {
			sprintf(options.kfname, "key-%d.aes", ++i);
		}
	}
	
	// Create file and write key+iv
	FILE *fv = fopen(options.kfname, "wb");
	if(fv == NULL) {
		printf("Error: Could not create key file. Aborting...\n");
		exit(EXIT_FAILURE);
	}
	uint16_t kl = (uint16_t)KEYLEN;
	fwrite(&kl, sizeof kl, 1, fv); // Write key size
	fwrite(config.key, 1, KEYLEN, fv); // Write key
	fwrite(config.iv, 1, AES_BLOCKLEN, fv); // Write IV
	fclose(fv); // Close file
	printf("Created key file \"%s\"\n", options.kfname); // Let user know name of key file

}

void DoKeyFile(struct CryptConfig config) {
	// If the user is encrypting data, output a key file (with the exception of password-only encryption)
	if( (options.e_flag && !options.key_flag) || (options.e_flag && options.g_flag) ) {
		writeKey(config);
	} else if(options.key_flag == FILE_MODE) {
		readKey(config);
	}
}

