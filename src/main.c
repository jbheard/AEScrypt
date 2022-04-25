/** AES encryption software
  *    @author Jacob Heard
  * 
  * Command line program to encrypt a file or directory using AES.
  *
  **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>

#include "cryptstructs.h"
#include "filequeue.h"
#include "utils.h"

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
	struct CryptSecrets secrets;
	secrets.password = NULL; // Must be NULL by default

	options.e_flag = 1; // encrypt by default

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
				strncpy(options.keyFilePath, optarg, 256); // Copy name to place
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
			case '?':
				// getopt_long already printed an error
				return EXIT_FAILURE;
				break;
			default: // This shouldn't happen
				exit(1);
				break;
		}
	}

	if(!options.key_flag && !options.e_flag) {
		printf("Please specify a key file or use password for decrypting.\n");
		return EXIT_FAILURE;
	}
	if(!options.r_flag && is_dir(path)) {
		printf("\"%s\" is a directory, to recursively encrypt all files, use -r\n");
		return EXIT_FAILURE;
	}
	
	if(options.e_flag) {
		int exists = (options.keyFilePath[0] != '\0' && access(options.keyFilePath, F_OK) == 0);
		if(options.g_flag && exists) {
			char choice[8] = {0};
			printf("The file \"%s\" will be overwritten, would you like to continue? (Y/N) ", options.keyFilePath);
			fgets(choice, 8, stdin);
			if(choice[0] != 'y' && choice[0] != 'Y') {
				printf("Aborting...\n");
				exit(EXIT_FAILURE);
			}
		} else if( !exists ) {
			// If the file does not exist, set the flag to create it
			options.g_flag = 1;
		}
	}
	
	if(options.key_flag == PASSWORD_MODE) {
		secrets.password = malloc(MAX_PASSWORD_LENGTH+1);
		getPassword(secrets.password);
	} else {
		if(gen_randoms((char*)secrets.key, MAX_KEY_SIZE) != 0) {
			printf("Error generating entropy for key\n");
			return EXIT_FAILURE;
		}
		v_print(2, "Generated key\n");
	}
	
	if(options.g_flag) {
		writeKeyFile(&secrets);
	} else if(options.key_flag == FILE_MODE) {
		readKeyFile(&secrets);
	}
	
	struct PathNode* start = pushNextPath(NULL, path);
	doAllFiles(start, secrets);

	free(secrets.password);

	return EXIT_SUCCESS;
}

