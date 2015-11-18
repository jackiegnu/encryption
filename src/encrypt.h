#ifndef H__ENCRYPT
#define H__ENCRYPT

void rijndaelEncrypt(const unsigned long *rk, int nrounds, const unsigned char plaintext[16], unsigned char ciphertext[16]);

#endif
