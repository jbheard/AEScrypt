/** AES encryption software
  *    @author Jacob Heard
  * 
  * Command line program to encrypt a file or directory using AES.
  *
  **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
  
#include "encrypt.h"
#include "scrypt.h"

#define PASSWORD_MODE  1
#define FILE_MODE      2

void GetConfigFromPassword(struct CryptConfig *config);
int handleOptions(const char *path);
void DoKeyFile(struct CryptConfig config);

void show_usage(char *name, int more) {
	printf("Usage: %s path [-r -e -d -p -g -k <keyfile> -m <mode>]\n", name);
	if(more) {
		printf("  Encrypts a file or directory using AES. Applies a given key or generates one randomly into a file.\n\n");
		printf("  path               Path to the file/directory to work on\n");
		printf("  -r, --recursive    Recursively work on files in directory\n");
		printf("  -e, --encrypt      Sets mode to encrypt given file/directory\n");
		printf("  -d, --decrypt      Sets mode to decrypt given file/directory\n");
		printf("  -p, --password     Prompt for password to use for key\n");
		printf("  -g, --gen-key      Generate a keyfile (use with -p to seed keyfile from pass)\n");
		printf("  -k, --keyfile      Load a key from file\n");
		printf("  -m, --mode         Sets cipher mode (128/192/256) default:128\n");
		printf("  -v(vv), --verbose  Run in verbose mode\n");
		printf("\n");
	} else {
		printf("Use %s --help to show help page.\n", name);	
	}
}

int main(int argc, char **argv) {
	if(argc < 2) {
		show_usage(argv[0], 0);
		return EXIT_SUCCESS;
	}
	/* Display help page on -h, --help */
	if(strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		show_usage(argv[0], 1);
		return EXIT_SUCCESS;
	}
	
	if(!is_file(argv[1]) && !is_dir(argv[1])) {
		printf("Error: Could not find \"%s\", please check that it is a file or directory and there are no typos.\n", argv[1]);
		return EXIT_FAILURE;
	}

	const char *path = argv[1];
	char *err; // Error handling for strtol
	int opt;

	options.e_flag = 1;

	static struct option long_options[] = {
		{"recursive", no_argument, 0, 'r'},
		{"encrypt", no_argument, 0, 'e'},
		{"decrypt", no_argument, 0, 'd'},
		{"gen-key", no_argument, 0, 'g'},
		{"password", no_argument, 0, 'p'},
		{"verbose", no_argument, 0, 'v'},
		{"keyfile", required_argument, 0, 'k'},
		{"mode", required_argument, 0, 'm'},
		{0, 0, 0, 0}
	};
	int option_index = 0;
	
	while(1) {
		// getopt_long stores the option index here.
		opt = getopt_long(argc, argv, "redgpvk:m:", long_options, &option_index);
		
		// Detect the end of the options. 
		if(opt == -1)
			break;

		switch(opt) {
			case 0:
				// If this option set a flag, do nothing else
				break;
			case 'r':
				options.r_flag = 1;
				break;
			case 'e':
				options.e_flag = 1;
				break;
			case 'd':
				options.e_flag = 0;
				break;
			case 'g':
				options.g_flag = 1;
				break;
			case 'p':
				options.key_flag = PASSWORD_MODE;
				break;
			case 'v':
				options.v_flag += 1;
				break;
			case 'k':
				strncpy(options.kfname, optarg, 256); // Copy name to place
				options.key_flag = FILE_MODE;
				break;
			case 'm':
				options.mode = (int) strtol(optarg, &err, 10);
				if(*err != '\0' || (options.mode != 128 && options.mode != 192 && options.mode != 256)) {
					printf("invalid argument '%s' should be one of (128/192/256)\n", optarg);
					return EXIT_FAILURE;
				} else {
					setAESMode(options.mode);
				}
				break;
			case '?': // When the user inevitably screws up an option
				// getopt_long already printed an error, we just exit
				return EXIT_FAILURE;
				break;
			default: // This shouldn't happen
				exit(1);
				break;
		}
	}

	return handleOptions(path);
}

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
		if(gen_randoms((char*)config.iv, BLOCKLEN) != 0) { // Generate an init vector
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

void GetConfigFromPassword(struct CryptConfig *config) {
	char pass[128] = {0};
	// Password mode; get password, set IV and key based on user input
	int len = getpass("password: ", pass, 128);
	if(options.e_flag) {
		char rep_pass[128] = {0};
		getpass("repeat  : ", rep_pass, 128);
		if( strcmp(pass, rep_pass) != 0 ) {
			printf("Passwords do not match, aborting...\n");
			exit(EXIT_FAILURE);
		}
	}
	v_print(2, "Creating and setting key.\n");

	// Scrypt variables
	struct ScryptInfo info;
	uint8_t *ptr;

	// Set up our parameters
	gen_randoms((char*)config->salt, 32);
	initScryptInfo(&info);
	info.salt = config->salt;
	info.slen = 32;
	info.dklen = BLOCKLEN + 32;

	// Run scrypt
	ptr = scrypt(pass, len, &info);

	// Use scrypt result for key and IV
	memcpy(config->key, ptr, 32);
	memcpy(config->iv, ptr+32, BLOCKLEN);
	free(ptr); // Clean up
}

void DoKeyFile(struct CryptConfig config) {
	// If the user is encrypting data, output a key file (with the exception of password-only encryption)
	if( (options.e_flag && !options.key_flag) || (options.e_flag && options.g_flag) ) {
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
		fwrite(config.iv, 1, BLOCKLEN, fv); // Write IV
		fclose(fv); // Close file
		printf("Created key file \"%s\"\n", options.kfname); // Let user know name of key file
	} else if(options.key_flag == FILE_MODE) {
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
		fread(config.iv, 1, BLOCKLEN, fv); //  Read IV
		fclose(fv); // Close file
		
		// In case we are in the wrong mode
		if(kl != KEYLEN) {
			printf("Inconsistent mode, changing to %d bit mode\n", kl*8);
			setAESMode(kl*8);
		}
	}
}

