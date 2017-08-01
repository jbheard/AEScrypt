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
		return EXIT_SUCCESS;
	}
	/* Display help page */
	if(strcmp(argv[1], "--help") == 0) {
		printf("Usage: %s path [-r -ed] [-p password] [-k keyfile] [-s]\n", argv[0]);
		printf("  Encrypts a file or directory using AES. Applies a given key or generates one randomly into a file.\n\n");
		printf("  path    The file/path to work on\n");
		printf("  -r      Recursively search files\n");
		printf("  -e      Sets mode to encrypt given file/directory\n");
		printf("  -d      Sets mode to decrypt given file/directory\n");
		printf("  -p      Sets seed for key to \"password\"\n");
		printf("  -k      Use \"keyfile\" for key\n");
		printf("  -s      Uses ECB over CBC version of AES. Less secure, can use password instead of keyfile.\n");
		printf("  -v(vv)  Verbose mode. Use more/less Vs depending on how verbose you want it.\n");
		printf("\n");
		return EXIT_SUCCESS;
	}
	
	/* This shouldn't happen, but idk. Maybe someone on *nix will try to encrypt a pipe or something */
	if(!is_file(argv[1]) && !is_dir(argv[1])) {
		printf("Error: Could not find \"%s\", please check that it is a file or directory and there are no typos.\n", argv[1]);
		return EXIT_FAILURE;
	}

	const char *path = argv[1]; // Descriptive alias for argv[1]
	if(gen_iv(iv_ptr) != 0) { // Generate an init vector
		printf("Error generating IV\n");
		return EXIT_FAILURE;
	}
	Iv = iv_ptr; // Set internal iv pointer to our own

	char kfname[256] = {0};
	int e_flag = 1, r_flag = 0, key_flag = 0;
	int c;
	FILE *fv = NULL;
	while((c = getopt (argc, argv, "vsredk:p:")) != -1) {
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
			case 'p':
				setKey(optarg, strlen(optarg));
				key_flag = 1;
				break;
			case 'k':
				strncpy(kfname, optarg, 256); // Copy name to place
				key_flag = 2;
				break;
			case '?':
				if(optopt == 'f' || optopt == 'k')
					printf("Option '-%c' requires an argument.\n", optopt);
				else
					printf("Unknown option: '-%c'\n", optopt);
				return EXIT_FAILURE;
				break;
			default:
				printf("An unknown error has ocurred.\n");
				return EXIT_FAILURE;
				break;
		}
	}
	
	// If the user does not provide a key to decrypt, use default
	if(!key_flag && e_flag == 0) {
		printf("Please specify a key file to use for decrypting.\n");
		return EXIT_FAILURE;
	} else if(!key_flag && ecb_flag) {
		/* Quick note about this, the only reason a user should use ECB mode is for a re-usable key. 
		 * This is more like a password that they can use rather than having to keep a file somewhere.
		 * ECB is conderably less secure than CBC mode, so if the user does not intend to remember a 
		 * password anyway, it is much more effective to use CBC AES.
		 */
		printf("To use ECB mode, you need to enter a key or key file.\nFor a randomly generated key, use the more secure CBC mode.\n");
		return EXIT_FAILURE;
	}

	// If we are in CBC mode and not decrypting, create key file
	if(!ecb_flag && e_flag) {
		v_print(1, "Creating key file...\n");
		int i = 1;
		
		// Create random seed for key
		if(!key_flag) {
			char tmp_key[32] = {0};
#ifdef _WIN32
			HCRYPTPROV hCryptProv = 0; // Crypto context
			if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) == 0) {
				printf("Error generating key.\n");
				return EXIT_FAILURE;
			}
			if(CryptGenRandom(hCryptProv, KEYLEN, (PBYTE)tmp_key) == 0) { // Generate random number
				printf("Error generating key.\n");
				return EXIT_FAILURE;
			}
#else
			//TODO verify this works on older *nix distros, or find workaround
			if(getrandom(tmp_key, KEYLEN, GRND_NONBLOCK) == -1) {
				printf("Error generating key.\n");
				return EXIT_FAILURE;
			}
#endif
			setKey(tmp_key, 11);
		}
		
		if(kfname[0] == '\0') { // If the key file name was not specified
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
		fwrite(&ecb_flag, sizeof ecb_flag, 1, fv); // Write mode
		fwrite(key, 1, 32, fv);
		if(!ecb_flag)
			fwrite(iv_ptr, 1, 32, fv);
		fclose(fv);
		
		printf("Created key file \"%s\"\n", kfname); // Let user know name of key file
	}
	else if(key_flag == 2 && !e_flag) { // A key file was specified for encryption
		// Open the file and read the key
		fv = fopen(kfname, "rb");
		if(fv == NULL) {
			printf("Error opening key file \"%s\".\n", kfname);
			return EXIT_FAILURE;
		}
		v_print(1, "Reading key from file.\n");
		fread(&ecb_flag, sizeof ecb_flag, 1, fv);
		fread(key, 1, 32, fv);
		if(!ecb_flag)
			fread(Iv, 1, 32, fv);
		fclose(fv);
	}
	
	if(!r_flag && !is_file(path)) {
		printf("Error: \"%s\" could not be found.\n", path);
		return EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}
