#include "../include/Cipher.h"
#include <stdio.h>

int main()
{
	Cipher cipher;
	//unsigned char szPlainStr[] = "A^G~o`'X";
	unsigned char szPlainStr[] = "test1234567890abcdefghijkl";
	unsigned char szHexToStr[1024];
	unsigned char szStrToHex[1024];
	unsigned char szEncStr[1024];
	unsigned char szDecStr[1024];
	char *pszBase64EncBuf = 0;
	unsigned char pszBase64DecBuf[500] = "";
	int iRet=0, i;
	
	memset(szHexToStr, 0, sizeof(szHexToStr));
	memset(szStrToHex, 0, sizeof(szStrToHex));
	memset(szEncStr, 0, sizeof(szEncStr));
	memset(szDecStr, 0, sizeof(szDecStr));
	
	printf("===================\n");                           
	printf("Cipher Module Test\n");
	printf("===================\n");
	printf("Cipher Value Test\n");
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("Function : cipher.StringToHex\n");
	printf("Plain Text : %s\n",szPlainStr);
	printf("Plain Text[0] : %d\n",szPlainStr[0]);	
	iRet = cipher.StringToHex(szStrToHex, szPlainStr);
	printf("StringToHex(Hex, Str) Result : %d\n",iRet);
	printf("Hex Text : %s\n", szStrToHex);
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("Function : cipher.HexToString\n");
	printf("Hex Text : %s\n",szStrToHex);
	iRet = cipher.HexToString(szHexToStr, szStrToHex);
	printf("HexToString(Str, Hex) Result : %d\n",iRet);
	printf("String Text : %s\n", szHexToStr);
	printf("String Text[0] : %d\n", szHexToStr[0]);
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("Function : cipher.Base64_Encode\n");
	printf("Plain Text : %s\n",szPlainStr);
	iRet = cipher.Base64_Encode(&pszBase64EncBuf, (char*)szPlainStr, strlen((char*)szPlainStr));
	printf("Base64_Encode(Buf, Plain, Len) Result : %d\n",iRet);
	printf("Base64_Encode Text : %s\n", pszBase64EncBuf);
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("Function : cipher.Base64_Decode\n");
	printf("Base64_Encode Text : %s\n",pszBase64EncBuf);
	iRet = cipher.Base64_Decode(pszBase64DecBuf, pszBase64EncBuf, sizeof(pszBase64DecBuf));
	printf("Base64_Decode(Dec, Enc, Len) Result : %d\n",iRet);
	printf("Base64_Decode Text : %s\n", pszBase64DecBuf);
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("Function : cipher.Encrypt2\n");
	printf("Plain Text : %s\n",szPlainStr);
	iRet = cipher.Encrypt2(szEncStr, szPlainStr, (unsigned char*)"1234567890123456");
	printf("Encrypt2(Enc, Plain, Key) Result : %d\n",iRet);
	printf("Encrypt Text : %s\n", szEncStr);
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("Function : cipher.Decrypt2\n");
	printf("Encrypt Text : %s\n",szEncStr);
	iRet = cipher.Decrypt2(szDecStr, szEncStr, (unsigned char*)"1234567890123456");
	printf("Decrypt2(Dec, Enc, Key) Result : %d\n",iRet);
	printf("Decrypt Text : %s\n", szDecStr);
	printf("Press Enter Key.\n");
	getchar();
	printf("=====================\n");
	printf("End.\n\n");
	return 0;
}