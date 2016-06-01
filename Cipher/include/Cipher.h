/*//////////////////////////////////////////////////////////////////////////////
// 개발자 : sjm
// 날짜 : 2015.01.16
// 명칭 : Cipher
// 기능 : 메세지를 암/복호화 한다.
//////////////////////////////////////////////////////////////////////////////*/

#ifndef _CIPHER_H_
#define _CIPHER_H_

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>

class Cipher
{
public:
	int Base64_Encode(char **encodedText, char *text, int numBytes);
	int Base64_Decode(unsigned char *dst, char *text, int numBytes);
	int Encrypt2(unsigned char* hexText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key);
	int Encrypt2(unsigned char* hexText, unsigned char* plainText, unsigned char* key);
	int Decrypt2(unsigned char* plainText, unsigned char* hexText, unsigned char* key);
	void CipherTest();
	int HexToString(unsigned char *szStr, const unsigned char *szHex);
	int HexToString(unsigned char *szStr, const unsigned char *szHex, int iLen);
	int StringToHex(unsigned char *szHex, const unsigned char *szStr);
	int StringToHex(unsigned char *szHex, const unsigned char *szStr, int iLen);
	int Encrypt(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key);
	int Decrypt(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key);
	Cipher();
	~Cipher();
};

#endif