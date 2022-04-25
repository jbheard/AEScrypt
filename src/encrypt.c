#include <stdlib.h>

#include "encrypt.h"
#include "cryptstructs.h"
#include "utils.h"

static int writeCryptHeader(
	struct CryptConfig *config,
	const char *checksum,
	FILE *fp
) {
	if(fwrite(&(config->version), 4, 1, fp) != 1)
		return 0;
	if(fwrite(config->iv, 1, AES_BLOCKLEN, fp) != AES_BLOCKLEN)
		return 0;
	if(fwrite(config->salt, 1, SALT_LEN, fp) != SALT_LEN)
		return 0;
	if(fwrite(checksum, 1, CHECKSUM_SIZE, fp) != CHECKSUM_SIZE)
		return 0;

	return 1;
}

static int readCryptHeader(
	struct CryptConfig *config,
	char *checksum,
	FILE *fp
) {
	if(fread(&(config->version), 4, 1, fp) != 1)
		return 0;
	if(fread(config->iv, 1, AES_BLOCKLEN, fp) != AES_BLOCKLEN)
		return 0;
	if(fread(config->salt, 1, SALT_LEN, fp) != SALT_LEN)
		return 0;
	if(fread(checksum, 1, CHECKSUM_SIZE, fp) != CHECKSUM_SIZE)
		return 0;

	return 1;
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
 * @param config The (en/de)crypt configuration to use
 * @param fp The open file pointer to the file to encrypt
 * @return 0 on success, nonzero on failure
 */
static int encrypt(
	const char *fname,
	struct CryptConfig config,
	struct CryptSecrets secrets,
	FILE *inputFile,
	FILE *tempFile
) {
	v_print(1, "Encrypting file \"%s\"\n", fname);

	v_print(3, "Allocating %d bytes for AES...\n", CHUNK_SIZE*2);
	uint8_t *output = malloc(CHUNK_SIZE); // Allocate chunk of memory for output
	uint8_t *input = malloc(CHUNK_SIZE);  // Allocate chunk of memory for input
	if(output == NULL || input == NULL) {
		output = (output) ? output : input; // Get the successful alloc (if there is one)
		if(output != NULL) free(output); // If one alloc worked and the other failed, free the successful one
		printf("Error allocating memory. Aborting...\n");
		return EXIT_FAILURE;
	}

	v_print(2, "Reading input file %s...\n", fname);
	uint32_t len, err, pad, rtotal = 0, wtotal = 0;
	Iv = config.iv;
	while( (len = fread(input, 1, CHUNK_SIZE, inputFile)) ) {
		pad = (AES_BLOCKLEN - (len % AES_BLOCKLEN)) % AES_BLOCKLEN;
		if(pad > 0) {
			// Put some zeroes into buffer for padding
			memset(input + len, 0, pad);
		}
		// Encrypt the buffer
		AES_CBC_encrypt_buffer(output, input, len+pad, secrets.key, 0);
		
		// Write size of data
		fwrite(&len, sizeof len, 1, tempFile);
		// Write actual data with padding
		fwrite(output, 1, len+pad, tempFile);
		rtotal += len;
		wtotal += len + pad + sizeof len;
	}
	v_print(2, "Read %d bytes as %d chunks. Wrote %d bytes.\n", rtotal, (rtotal / CHUNK_SIZE)+1, wtotal);
		
	v_print(3, "Freeing AES memory...\n");
	free(input);
	free(output);
	
	v_print(1, "Done encrypting \"%s\"\n\n", fname);
	
	return EXIT_SUCCESS;
}

/**
 * Accepts a file that was encrypted using encrypt()
 * Decrypts the file and keeps the original file name
 * 
 * @param fname The name of the file to decrypt
 * @param config The (en/de)crypt configuration to use
 * @param fp The open file pointer to the encrypted file
 * @return 0 on success, nonzero on failure
 */
static int decrypt(
	const char *fname,
	struct CryptConfig config,
	struct CryptSecrets secrets,
	FILE *inputFile,
	FILE *tempFile
) {
	v_print(1, "Decrypting file \"%s\"\n", fname);	
	v_print(3, "Allocating %d bytes for AES...\n", CHUNK_SIZE*2);

	uint8_t *output = malloc(CHUNK_SIZE); // Allocate chunk of memory for output
	uint8_t *input = malloc(CHUNK_SIZE);  // Allocate chunk of memory for input
	if(output == NULL || input == NULL) {
		output = (output) ? output : input; // Get the successful alloc (if there is one)
		if(output != NULL) free(output); // If one alloc worked and the other failed, free the successful one
		printf("Error allocating memory. Aborting...\n");
		return EXIT_FAILURE;
	}

	v_print(2, "Reading %s...\n", fname);
	
	uint32_t len, err, pad, rtotal = 0, wtotal = 0;
	Iv = config.iv; // Set iv initially, AES_CBC_decrypt_buffer will update as necessary
	// Read size of data in loop
	while( fread(&len, sizeof len, 1, inputFile) ) {
		pad = (AES_BLOCKLEN - (len % AES_BLOCKLEN)) % AES_BLOCKLEN; // Get size of padding
		// Read correct number of bytes into buffer
		err = fread(input, 1, len+pad, inputFile);
		if(err != len+pad) {
			printf("Error: File read issue.\n");
			return EXIT_FAILURE;
		}
		// Decrypt the data
		AES_CBC_decrypt_buffer(output, input, len+pad, secrets.key, 0);
		// Write only the data to output (not zero padding)
		fwrite(output, 1, len, tempFile);
		rtotal += len + pad + sizeof len;
		wtotal += len;
	}
	v_print(2, "Read %d bytes as %d chunks. Wrote %d bytes.\n", rtotal, (rtotal / CHUNK_SIZE)+1, wtotal);
	
	v_print(3, "Freeing AES memory...\n");
	free(output);
	free(input);
	
	v_print(1, "Done working on \"%s\"\n\n", fname);

	return EXIT_SUCCESS;
}

void decryptFile(const char *path, struct CryptSecrets secrets) {
	struct CryptConfig config;
	char checksumActual[CHECKSUM_SIZE];
	char checksum[CHECKSUM_SIZE];

	FILE* inputFile = fopen(path, "rb");
	if(inputFile == NULL) {
		v_print(1, "Error opening file.\n");
		exit(EXIT_FAILURE);
	}
	
	if(!readCryptHeader(&config, checksum, inputFile)) {
		printf("Malformed header. Aborting...\n");
		fclose(inputFile);
		exit(EXIT_FAILURE);
	}
	
	if(secrets.password) {
		getConfigFromPassword(&config, &secrets);
	}

	sha256((char*)secrets.key, checksumActual, KEYLEN);	
	if(memcmp(checksumActual, checksum, CHECKSUM_SIZE) != 0) {
		printf("Invalid checksum, quitting.\n");
		fclose(inputFile);
		exit(EXIT_FAILURE);
	}
	
	v_print(2, "Creating temp file...\n");
	char tempFileName[32] = {0};
	FILE *tempFile = getTempFile(tempFileName);
	if(tempFile == NULL) {
		printf("Error creating temp file, aborting...");
		fclose(inputFile);
		exit(EXIT_FAILURE);
	}
	
	int status = decrypt(path, config, secrets, inputFile, tempFile);
	
	v_print(3, "Closing \"%s\"...\n", path);
	fclose(inputFile);
	v_print(3, "Closing \"%s\"...\n", tempFileName);
	fclose(tempFile);
	
	if(status != EXIT_SUCCESS)
		exit(status);

	v_print(2, "Replacing \"%s\" with temp file...\n", path);
	replace(tempFileName, path);
}

void encryptFile(const char *path, struct CryptSecrets secrets) {
	struct CryptConfig config;
	char checksum[CHECKSUM_SIZE];
	
	FILE* inputFile = fopen(path, "rb+");
	if(inputFile == NULL) {
		v_print(1, "Error opening file.\n");
		exit(EXIT_FAILURE);
	}

	gen_randoms((char*)config.salt, SALT_LEN);
	if(secrets.password) {
		getConfigFromPassword(&config, &secrets);
	} else {
		if(gen_randoms((char*)config.iv, AES_BLOCKLEN) != 0) {
			printf("Error generating IV\n");
			exit(EXIT_FAILURE);
		}
	}
	
	v_print(2, "Creating temp file...\n");
	char tempFileName[32] = {0};
	FILE *tempFile = getTempFile(tempFileName);
	if(tempFile == NULL) {
		printf("Error creating temp file, aborting...");
		fclose(inputFile);
		exit(EXIT_FAILURE);
	}
	
	v_print(2, "Writing file header...\n");
	sha256((char*)secrets.key, checksum, KEYLEN);
	if(!writeCryptHeader(&config, checksum, tempFile)) {
		printf("Error writing header information. Aborting...\n");
		fclose(tempFile);
		remove(tempFileName);
		exit(EXIT_FAILURE);
	}
	
	int status = encrypt(path, config, secrets, inputFile, tempFile);

	v_print(3, "Closing \"%s\"...\n", path);
	fclose(inputFile);
	v_print(3, "Closing temp file...\n", tempFileName);
	fclose(tempFile);

	if(status != EXIT_SUCCESS)
		exit(status);
	
	v_print(2, "Replacing \"%s\" with temp file...\n", path);
	replace(tempFileName, path);
}

