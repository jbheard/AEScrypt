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
	
	/* This shouldn't happen, but idk. Maybe someone on *nix will try to encrypt a pipe or something */
	if(!is_file(argv[1]) && !is_dir(argv[1])) {
		printf("Error: Could not find \"%s\", please check that it is a file or directory and there are no typos.\n", argv[1]);
		return EXIT_FAILURE;
	}

	const char *path = argv[1]; // Descriptive alias for argv[1]
	char kfname[256] = {0}, pass[128] = {0};
	char *err; // Error handling for strtol
	static int e_flag = 1, r_flag = 0, key_flag = 0;
	static int g_flag = 0, mode;
	int c, len;
	FILE *fv = NULL;

	Iv = iv_ptr; // Set internal iv pointer to our buffer

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
		c = getopt_long(argc, argv, "redgpvk:m:", long_options, &option_index);
		
		// Detect the end of the options. 
		if(c == -1)
			break;

		switch(c) {
			case 0:
				// If this option set a flag, do nothing else
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
			case 'g':
				g_flag = 1;
				break;
			case 'p':
				key_flag = PASSWORD_MODE;
				break;
			case 'v':
				v_flag += 1;
				break;
			case 'k':
				strncpy(kfname, optarg, 256); // Copy name to place
				key_flag = FILE_MODE;
				break;
			case 'm':
				mode = (int) strtol(optarg, &err, 10);
				if(*err != '\0' || (mode != 128 && mode != 192 && mode != 256)) {
					printf("invalid argument '%s' should be one of (128/192/256)\n", optarg);
					return EXIT_FAILURE;
				} else {
					setAESMode(mode);
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
	
	// If the user does not provide a key to decrypt, die
	if(!key_flag && !e_flag) {
		printf("Please specify a key file to use for decrypting.\n");
		return EXIT_FAILURE;
	}

	// Password mode; get password, set IV and key based on user input
	if(key_flag == PASSWORD_MODE) {
		len = getpass("password: ", pass, 128);
		v_print(2, "Creating and setting key.\n");
		
		// Scrypt variables
		struct ScryptInfo info;
		uint8_t salt[32], *ptr;

		// Set up our parameters
		gen_randoms((char*)salt, 32);
		initScryptInfo(&info);
		info.salt = salt;
		info.slen = 32;
		info.dklen = BLOCKLEN + 32;

		// Run scrypt
		ptr = scrypt(pass, len, &info);

		// Use scrypt result for key and IV
		memcpy(key, ptr, 32);
		memcpy(iv_ptr, ptr+32, BLOCKLEN);
		free(ptr); // Clean up
	} else if(e_flag) { // If we are encrypting and NOT using a password, generate IV randomly
		v_print(2, "Generating AES initialization vector.\n");
		if(gen_randoms((char*)iv_ptr, BLOCKLEN) != 0) { // Generate an init vector
			printf("Error generating IV\n");
			return EXIT_FAILURE;
		}
	}
	
	// Check if file name was selected
	if(e_flag && kfname[0] != '\0') { 
		int a = (access(kfname, F_OK) == 0);
		if(g_flag && a) {
			char b[8] = {0};
			printf("The file \"\" will be overwritten, would you like to continue? (Y/N) ");
			fgets(b, 8, stdin);
			if(b[0] != 'y' && b[0] != 'Y') { // Continue when input is 'y', or 'Y'
				printf("Aborting...\n");
				exit(EXIT_FAILURE);
			}
		}
		else if( !a ) { // If the file does not exist, set the flag to create it
			g_flag = 1;
		}
	}

	// If the user is encrypting data, output a key file (with the exception of password-only encryption)
	if( (e_flag && !key_flag) || (e_flag && g_flag) ) {
		v_print(1, "Creating key file...\n");
		int i = 1;
		
		// Create random seed for key
		if(key_flag != PASSWORD_MODE) { // If we didn't already get a password for this
			if(gen_randoms((char*)key, KEYLEN) != 0) {
				printf("Error generating entropy for key\n");
				return EXIT_FAILURE;
			}
		}
		
		// If the key file name was not specified
		if(kfname[0] == '\0') {
			// Get unused name for file
			sprintf(kfname, "key-%d.aes", i);
			while(access(kfname, F_OK) != -1) {
				sprintf(kfname, "key-%d.aes", ++i);
			}
		}
		
		// Create file and write key+iv
		fv = fopen(kfname, "wb");
		if(fv == NULL) {
			printf("Error: Could not create key file. Aborting...\n");
			return EXIT_FAILURE;
		}
		uint16_t kl = (uint16_t)KEYLEN;
		fwrite(&kl, sizeof kl, 1, fv); // Write key size
		fwrite(key, 1, KEYLEN, fv); // Write key
		fwrite(iv_ptr, 1, BLOCKLEN, fv); // Write IV
		fclose(fv); // Close file
		printf("Created key file \"%s\"\n", kfname); // Let user know name of key file
	}
	else if(key_flag == FILE_MODE) { // A key file was specified for encryption
		// Open the file and read the key
		fv = fopen(kfname, "rb");
		if(fv == NULL) {
			printf("Error opening key file \"%s\".\n", kfname);
			return EXIT_FAILURE;
		}
		uint16_t kl;
		v_print(1, "Reading key from file.\n");
		fread(&kl, sizeof kl, 1, fv); // Get key size
		fread(key, 1, kl, fv); // Read key
		fread(iv_ptr, 1, BLOCKLEN, fv); //  Read IV
		fclose(fv); // Close file
		
		// In case we are in the wrong mode
		if(kl != KEYLEN) {
			printf("Inconsistent mode, changing to %d bit mode\n", kl*8);
			setAESMode(kl*8);
		}
	}
	
	if(!r_flag && !is_file(path)) {
		printf("Error: \"%s\" could not be found.\n", path);
		return EXIT_FAILURE;
	}
	if(r_flag) // Recursively find and encrypt/decrypt files
		traverse(path, e_flag);
	else if(is_file(path)) { // Make sure we are working with a file
		if(e_flag) // Encrypt
			encrypt(path);
		else       // Decrypt
			decrypt(path);
	} else { // If we weren't given a file
		printf("Error: \"%s\" is not a file\n", path);
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}
