#ifndef UTILS_H_
#define UTILS_H_

#include "encrypt.h"

#define PASSWORD_MODE  1
#define FILE_MODE      2

void getPassword(char*);
void GetConfigFromPassword(struct CryptConfig*);
int handleOptions(const char*);
void DoKeyFile(struct CryptConfig);

#endif // UTILS_H_