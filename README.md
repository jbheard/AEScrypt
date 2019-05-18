# AEScrypt
Cross platform command line tool to encrypt/decrypt files with AES (ECB or CBC).

Compile with "gcc aes.c sha256.c encrypt.c -Werror -Wall"  

The tool can encrypt files and directories and take a user specified key or use the default. The initialization vector in CBC mode is stored with the key in a file. This file cannot be re-created as the IV is completely random, so don't lose this file if in CBC mode (default).

Credit to [kokke's Tiny AES](https://github.com/kokke/tiny-AES128-C) and [B-con's crypto-algorithms](https://github.com/B-Con/crypto-algorithms). 

NOTICE: This tool was created as a learning experience. While the algorithms used are standardized, it is still possible vulnerabilities remain in the program.
