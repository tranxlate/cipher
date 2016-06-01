/*****************************************************************
Copyright (c) 2016 Jung-Min, Shin (tranxlate3@gmail.com)

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*****************************************************************/


#ifdef WIN32
#include "Cipher.h"
#else
#include "../include/Cipher.h"
#endif


// Hex Table
static const unsigned char arcHex1[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static const unsigned char arcHex2[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
static const unsigned char arcNum[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};


/*------ Base64 Encoding Table ------*/
static const char MimeBase64[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};
/*------ Base64 Decoding Table ------*/
static int DecodeMimeBase64[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

/*//////////////////////////////////////////////////////////////////////////////
//
// 				External Functions
//
//////////////////////////////////////////////////////////////////////////////*/

int Cipher::Base64_Encode( char **encodedText, char *text, int numBytes)
{
  unsigned char input[3]  = {0,0,0};
  unsigned char output[4] = {0,0,0,0};
  int   index, i, j, size;
  char *p, *plen;
  plen           = text + numBytes - 1;
  size           = (4 * (numBytes / 3)) + (numBytes % 3? 4 : 0) + 1;
  (*encodedText) = (char*)malloc(size);
  j              = 0;
    for  (i = 0, p = text;p <= plen; i++, p++) {
        index = i % 3;
        input[index] = *p;
        if (index == 2 || p == plen) {
            output[0] = ((input[0] & 0xFC) >> 2);
            output[1] = ((input[0] & 0x3) << 4) | ((input[1] & 0xF0) >> 4);
            output[2] = ((input[1] & 0xF) << 2) | ((input[2] & 0xC0) >> 6);
            output[3] = (input[2] & 0x3F);
            (*encodedText)[j++] = MimeBase64[output[0]];
            (*encodedText)[j++] = MimeBase64[output[1]];
            (*encodedText)[j++] = index == 0? '=' : MimeBase64[output[2]];
            (*encodedText)[j++] = index <  2? '=' : MimeBase64[output[3]];
            input[0] = input[1] = input[2] = 0;
        }
    }
    (*encodedText)[j] = '\0';
    return size;
}


int Cipher::Base64_Decode(unsigned char *dst, char *text, int numBytes )
{
  const char* cp;
  int space_idx = 0, phase;
  int d, prev_d = 0;
  unsigned char c;
    space_idx = 0;
    phase = 0;
    for ( cp = text; *cp != '\0'; ++cp ) {
        d = DecodeMimeBase64[(int) *cp];
        if ( d != -1 ) {
            switch ( phase ) {
                case 0:
                    ++phase;
                    break;
                case 1:
                    c = ( ( prev_d << 2 ) | ( ( d & 0x30 ) >> 4 ) );
                    if ( space_idx < numBytes )
                        dst[space_idx++] = c;
                    ++phase;
                    break;
                case 2:
                    c = ( ( ( prev_d & 0xf ) << 4 ) | ( ( d & 0x3c ) >> 2 ) );
                    if ( space_idx < numBytes )
                        dst[space_idx++] = c;
                    ++phase;
                    break;
                case 3:
                    c = ( ( ( prev_d & 0x03 ) << 6 ) | d );
                    if ( space_idx < numBytes )
                        dst[space_idx++] = c;
                    phase = 0;
                    break;
            }
            prev_d = d;
        }
    }
    return space_idx;
}

int Cipher::Encrypt2(unsigned char* hexText, unsigned char* plainText, unsigned char* key)
{
	return Encrypt2(hexText, plainText, strlen((char *)plainText), key);
}

int Cipher::Encrypt2(unsigned char* hexText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key)
{
	const int iCutLen = 15;
	unsigned int iEncLen = 0, iEncLenTemp = 0;
	unsigned int iLoopCnt = (plainTextLen - 1) / iCutLen + 1;
	unsigned int startIdx, endIdx;
	unsigned int i, j, k, cpyidx=0;
	unsigned char plainTextBuf[17] = "";
	unsigned char cipherTextBuf[33] = "";
	unsigned char hexTextBuf[65] = "";

	if(strlen((char*)plainText)<=iCutLen)
	{
		//printf("under 15\n");
		//printf("%s/%s/%d/%s\n",cipherTextBuf, plainText, plainTextLen, key);
		iEncLen = Encrypt(cipherTextBuf, plainText, plainTextLen, key);
		//printf("%s/%s/%d\n",hexText, cipherTextBuf, iEncLen);
		StringToHex(hexText, cipherTextBuf, iEncLen);
		//printf("return hex:%s\n", hexText);
	}
	else
	{
		for(i=1;i<=iLoopCnt;i++)
		{
			//printf("over 15\n");
			startIdx = (i-1) * iCutLen;
			endIdx = i * iCutLen;
			if(endIdx > plainTextLen) endIdx = plainTextLen;
			memset(plainTextBuf, 0, sizeof(plainTextBuf));
			memset(cipherTextBuf, 0, sizeof(cipherTextBuf));
			memset(hexTextBuf, 0, sizeof(hexTextBuf));
			for(j=startIdx,k=0;j<endIdx;j++,k++) plainTextBuf[k] = plainText[j];
			iEncLenTemp = Encrypt(cipherTextBuf, plainTextBuf, strlen((char*)plainTextBuf), key);
			iEncLen += iEncLenTemp;
			StringToHex(hexTextBuf, cipherTextBuf, iEncLenTemp);
			strcat((char*)hexText, (char*)hexTextBuf);
			//strcat((char*)cipherText, (char*)cipherTextBuf);
			/*
			for(j=0;j<strlen((char*)cipherTextBuf);j++)
			{
				cipherText[cpyidx] = cipherTextBuf[j];
				cpyidx++;
			}
			*/
		}
	}
	return iEncLen;
}

int Cipher::Decrypt2(unsigned char* plainText, unsigned char* hexText, unsigned char* key)
{
	const int iHexSize = 32;
	unsigned int iHexTextLen = strlen((char*)hexText);
	unsigned int iDecLen = 0, iStrLen = 0;
	unsigned int iLoopCnt = (strlen((char*)hexText) - 1) / iHexSize + 1;
	unsigned int startIdx, endIdx;
	unsigned int i, j, k, cpyidx=0;
	unsigned char plainTextBuf[200] = "";
	unsigned char cipherTextBuf[33] = "";
	unsigned char hexTextBuf[iHexSize+1] = "";
	
	if(strlen((char*)hexText)<=iHexSize)
	{
		iStrLen = HexToString(cipherTextBuf, hexText);
		return Decrypt(plainText, cipherTextBuf, iStrLen, key);
	}
	else
	{
		for(i=1;i<=iLoopCnt;i++)
		{
			startIdx = (i-1) * iHexSize;
			endIdx = i * iHexSize;
			if(endIdx > iHexTextLen) endIdx = iHexTextLen;
			memset(plainTextBuf, 0, sizeof(plainTextBuf));
			memset(cipherTextBuf, 0, sizeof(cipherTextBuf));
			memset(hexTextBuf, 0, sizeof(hexTextBuf));
			for(j=startIdx,k=0;j<endIdx;j++,k++) hexTextBuf[k] = hexText[j];
			iStrLen = HexToString(cipherTextBuf, hexTextBuf);
			iDecLen += Decrypt(plainTextBuf, cipherTextBuf, iStrLen, key);
			//strcat((char*)plainText, (char*)plainTextBuf);
			
			for(j=0;j<strlen((char*)plainTextBuf);j++)
			{
				plainText[cpyidx] = plainTextBuf[j];
				cpyidx++;
			}
			
		}
	}
	return iDecLen;
}


/*//////////////////////////////////////////////////////////////////////////////
// 개발자 : sjm
// 날짜 : 2015.03.19
// 명칭 : Hex to String
// 기능 : 헥사코드를 문자열로 변환.
//////////////////////////////////////////////////////////////////////////////*/

int Cipher::HexToString(unsigned char *szStr, const unsigned char *szHex, int iLen)
{
	int i, j, idx=0;
	unsigned char op1, op2;
	unsigned char c;

	if(iLen < 2) 
		return 0;
		
	for(i=0;i<iLen;i+=2)
	{
		op1=-1;
		for(j=0;j<16;j++)
		{
			if(arcHex1[j]==szHex[i] || arcHex2[j]==szHex[i])
			{
				op1 = arcNum[j] * 16;
				break;
			}
		}
		if(op1==-1) return -1;
		op2=-1;
		for(j=0;j<16;j++)
		{
			if(arcHex1[j]==szHex[i+1] || arcHex2[j]==szHex[i+1])
			{
				op2 = arcNum[j];
				break;
			}
		}
		if(op2==-1) return -1;
//printf("Debug op1:%d, op2:%d\n",op1,op2);
		c = op1+op2;
		szStr[idx++] = c;
	}
	szStr[idx] = 0;
	return idx;
}

int Cipher::HexToString(unsigned char *szStr, const unsigned char *szHex)
{
	int i, j, idx=0;
	unsigned char op1, op2;
	unsigned char c;
	
	if(strlen((char*)szHex) < 2) return 0;
	for(i=0;i<strlen((char*)szHex);i+=2)
	{
		//op1=-1;
		for(j=0;j<16;j++)
		{
			if(arcHex1[j]==szHex[i] || arcHex2[j]==szHex[i])
			{
				op1 = arcNum[j] * 16;
				break;
			}
		}
		//if(op1==-1) return -1;
		//op2=-1;
		for(j=0;j<16;j++)
		{
			if(arcHex1[j]==szHex[i+1] || arcHex2[j]==szHex[i+1])
			{
				op2 = arcNum[j];
				break;
			}
		}
		//if(op2==-1) return -1;
//printf("Debug op1:%d, op2:%d\n",op1,op2);
		c = op1+op2;
		szStr[idx++] = c;
	}
	szStr[idx] = 0;
	return idx;
}


/*//////////////////////////////////////////////////////////////////////////////
// 개발자 : sjm
// 날짜 : 2015.03.19
// 명칭 : String to Hex
// 기능 : 문자열을 헥사코드로 변환.
//////////////////////////////////////////////////////////////////////////////*/

int Cipher::StringToHex(unsigned char *szHex, const unsigned char *szStr, int iLen)
{
	int i, j, idx=0;
	unsigned char op1, op2;
	unsigned char c;
	
	
	//printf("%s/%s/%d\n", szHex, szStr, iLen);
	for(i=0;i<iLen;i++)
	{
		op1 = szStr[i] / 16;
		op2 = szStr[i] % 16;
		//printf("Debug op1:%d, op2:%d\n",op1,op2);
		//printf("Debug Hex[op1]:%c, Hex[op2]:%c\n",arcHex1[op1],arcHex1[op2]);
		
		szHex[idx++] = arcHex2[op1];
		szHex[idx++] = arcHex2[op2];
	}
	szHex[idx] = 0;
	//printf("hex:%s\n", szHex);
	return strlen((char*)szHex);
}


int Cipher::StringToHex(unsigned char *szHex, const unsigned char *szStr)
{
	int i, j, idx=0;
	unsigned char op1, op2;
	unsigned char c;
	
	for(i=0;i<strlen((char*)szStr);i++)
	{
		op1 = szStr[i] / 16;
		op2 = szStr[i] % 16;
		
		szHex[idx++] = arcHex2[op1];
		szHex[idx++] = arcHex2[op2];
	}
	szHex[idx] = 0;
	return strlen((char*)szHex);
}


/*//////////////////////////////////////////////////////////////////////////////
// 개발자 : sjm
// 날짜 : 2015.01.16
// 명칭 : Encrypt
// 기능 : 메세지를 암호화 한다.
//////////////////////////////////////////////////////////////////////////////*/

/*  AES Encrypt Process */  
int Cipher::Encrypt(unsigned char* cipherText, unsigned char* plainText, unsigned int plainTextLen, unsigned char* key)   
{   
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));   
    int addLen = 0, orgLen = 0;   
    unsigned long err = 0;  
    ERR_load_crypto_strings();   
    EVP_CIPHER_CTX_init(ctx);  
    if(EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, NULL) != 1) {   
        err = ERR_get_error();   
        printf("ERR : EVP_Encrypt() - %s\n", ERR_error_string(err, NULL));   
        return -1;   
    }  
    if(EVP_EncryptUpdate(ctx, cipherText, &orgLen, plainText, plainTextLen) != 1) {   
        err = ERR_get_error();   
        printf("ERR : EVP_EncryptUpdate() - %s\n", ERR_error_string(err, NULL));   
        return -1;   
    }  
    if (EVP_EncryptFinal(ctx, cipherText + orgLen, &addLen) != 1) {   
        err = ERR_get_error();   
        printf("ERR: EVP_EncryptFinal() - %s\n", ERR_error_string (err, NULL));   
        return -1;   
    }  
    EVP_CIPHER_CTX_cleanup(ctx);   
    ERR_free_strings();
	if(ctx) free(ctx);
    return addLen + orgLen;   
}

/*//////////////////////////////////////////////////////////////////////////////
// 개발자 : sjm
// 날짜 : 2015.01.16
// 명칭 : Decrypt
// 기능 : 메세지를 복호화 한다.
//////////////////////////////////////////////////////////////////////////////*/

/*  AES Decrypt Process */
int Cipher::Decrypt(unsigned char* plainText, unsigned char* cipherText, unsigned int cipherTextLen, unsigned char* key)   
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));   
    unsigned long err = 0;   
    int toLen = 0;
    int outLen = 0;
    ERR_load_crypto_strings();   
    EVP_CIPHER_CTX_init(ctx);  
    if (EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, NULL) != 1) {   
        err = ERR_get_error();   
        printf("ERR: EVP_DecryptInit() - %s\n", ERR_error_string (err, NULL));   
        return -1;   
    }   
    if (EVP_DecryptUpdate(ctx, plainText, &toLen, cipherText, cipherTextLen) != 1) {   
        err = ERR_get_error();     
        printf("ERR: EVP_DecryptUpdate() - %s\n", ERR_error_string (err, NULL));   
        return -1;   
    }  
    if (EVP_DecryptFinal(ctx, &plainText[cipherTextLen], &outLen) != 1) {   
        err = ERR_get_error();   
        printf("ERR: EVP_DecryptFinal() - %s\n", ERR_error_string (err, NULL));   
        return -1;   
    }  
    EVP_CIPHER_CTX_cleanup(ctx);   
    ERR_free_strings();
	if(ctx) free(ctx);
    plainText[toLen + outLen] = 0;
    return toLen + outLen;   
}

void Cipher::CipherTest()
{
	int i;
	for(i=0;i<16;i++)
	{
		printf("Debug Hex1[%d]:%c, Hex2[%d]:%c, Num[%d]:%d\n", i, arcHex1[i], i, arcHex2[i], i, arcNum[i]);
	}
}

Cipher::Cipher()
{
}

Cipher::~Cipher()
{
}

