#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define IN
#define OUT

#define HASHFUNC mabowenhash
#define HASHBLOCKLEN 16

int mabowenhash(unsigned char *indata, unsigned int indatalen, 
				unsigned char *outdata, unsigned int *outdatalen) {
					
	if (NULL == indata || NULL == outdata || 0 == indatalen || 0 == *outdatalen) {
		printf("error: indata invalid.\n");
		return 1;
	}
	
	int ret;
	int i, j;
	int flag = indatalen % HASHBLOCKLEN ? indatalen / HASHBLOCKLEN + 1 : indatalen / HASHBLOCKLEN;
	/////// log ///////
	printf("flag:%d\n", flag);
	/////// log ///////
	int padlen;
	unsigned int templen;
	unsigned char *paddingindata = NULL;
	unsigned int paddingindatalen = indatalen;
	unsigned char temphash[HASHBLOCKLEN] = { 0 };
	unsigned char tempdata[HASHBLOCKLEN] = { 0 };
	
	paddingindata = (unsigned char *)malloc(indatalen + 16);
	
	//padding
	if (indatalen % HASHBLOCKLEN) {
		padlen = HASHBLOCKLEN - indatalen % HASHBLOCKLEN;
		memcpy(paddingindata, indata, indatalen);
		memset(paddingindata + indatalen, 0x00, padlen);
		paddingindatalen += padlen;
	}
	
	/////// log ///////
	printf("paddingindata:\n");
	for(i = 0; i < paddingindatalen; i++)
		printf("%02x ", *(paddingindata + i));
	printf("\nend\n");
	/////// log ///////
	
	for (i = 0; i < flag; i++) {
		memcpy(tempdata, paddingindata + i * 16, HASHBLOCKLEN);
		
		/////// log ///////
		printf("tempdata:\n");
		for(j = 0; j < HASHBLOCKLEN; j++)
			printf("%02x ", tempdata[j]);
		printf("\nend\n");
		/////// log ///////
		
		for (j = 0; j < HASHBLOCKLEN; j++) {
			temphash[j] ^= tempdata[j];
		}
		
		/////// log ///////
		printf("temphash:\n");
		for(j = 0; j < HASHBLOCKLEN; j++)
			printf("%02x ", temphash[j]);
		printf("\nend\n");
		/////// log ///////
	}
	
	memcpy(outdata, tempdata, HASHBLOCKLEN);
	*outdatalen = HASHBLOCKLEN;
	
	free(paddingindata);
	
	return 0;
}

int HMAC(IN unsigned char *key, IN unsigned int keylen,
		 IN unsigned char *message, IN unsigned int messagelen,
		 OUT unsigned char *hmac, OUT unsigned int *hmaclen) {
	
	int ret;
	int i;
	int keypaddinglen;
	unsigned char opad = 0x5A;
	unsigned char ipad = 0x36;
	unsigned int hash1len = HASHBLOCKLEN;
	unsigned int hash2len = HASHBLOCKLEN;
	unsigned char padkey[HASHBLOCKLEN];
	unsigned char *opadxorpadkey;
	unsigned char *ipadxorpadkey;
	unsigned char *hash1;
	unsigned char *hash2;
	
	opadxorpadkey = (unsigned char *)malloc(HASHBLOCKLEN * 2);
	ipadxorpadkey = (unsigned char *)malloc(HASHBLOCKLEN + messagelen);
	hash1 = (unsigned char *)malloc(HASHBLOCKLEN);
	hash2 = (unsigned char *)malloc(HASHBLOCKLEN);
	
	memcpy(padkey, key, keylen);
	
	//keypadding
	if (keylen < HASHBLOCKLEN) {
		keypaddinglen = HASHBLOCKLEN - keylen;
		memset(padkey + keylen, 0x00, keypaddinglen);
	}
	
	//ipad ^ key
	for (i = 0; i < HASHBLOCKLEN; i++) {
		*(ipadxorpadkey + i) = *(padkey + i) ^ ipad;
	}
	
	/////// log ///////
	printf("ipadxorpadkey:\n");
	for(i = 0; i < HASHBLOCKLEN; i++)
		printf("%02x ", *(ipadxorpadkey + i));
	printf("\nend\n");
	/////// log ///////
	
	//opad ^ key
	for (i = 0; i < HASHBLOCKLEN; i++) {
		*(opadxorpadkey + i) = *(padkey + i) ^ opad;
	}
	
	/////// log ///////
	printf("opadxorpadkey:\n");
	for(i = 0; i < HASHBLOCKLEN; i++)
		printf("%02x ", *(opadxorpadkey + i));
	printf("\nend\n");
	/////// log ///////
	
	//concatenate ipadxorpadkey with message
	memcpy(ipadxorpadkey + HASHBLOCKLEN, message, messagelen);
	
	//hash concatenated ipadxorpadkey-message
	ret = HASHFUNC(ipadxorpadkey, HASHBLOCKLEN + messagelen, hash1, &hash1len);
	if (ret) {
		printf("ret\n");
		return ret;
	}
	
	//concatenate opadxorpadkey with HashedIpadXorData
	memcpy(opadxorpadkey + HASHBLOCKLEN, hash1, hash1len);
	
	/////// log ///////
	printf("opadxorpadkey:\n");
	for(i = 0; i < hash1len; i++)
		printf("%02x ", *(opadxorpadkey + i));
	printf("\nend\n");
	/////// log ///////
	
	//hash final data
	ret = HASHFUNC(opadxorpadkey, HASHBLOCKLEN * 2, hash2, &hash2len);
	if (ret) {
		printf("ret\n");
		return ret;
	}
	
	/////// log ///////
	printf("hash2:\n");
	for(i = 0; i < hash2len; i++)
		printf("%02x ", hash2 + i);
	printf("\nend\n");
	/////// log ///////
	
	memcpy(hmac, hash2, HASHBLOCKLEN);
	*hmaclen = HASHBLOCKLEN;
	
	free(opadxorpadkey);
	free(ipadxorpadkey);
	free(hash1);
	free(hash2);
	
	return ret;
}

int main() {
	int ret;
	int i;
	unsigned char key[HASHBLOCKLEN] = "1234567812345678";
	unsigned int keylen = HASHBLOCKLEN;
	unsigned char *message = "mabowenidsahfudhsuiafhodshauifhdsoiahfiuosd";
	unsigned int messagelen = 43;
	unsigned char hmacdata[HASHBLOCKLEN] = {0};
	unsigned int hmacdatalen = HASHBLOCKLEN;
	
	ret = HMAC(key, keylen, message, messagelen, hmacdata, &hmacdatalen);
	if (ret) {
		printf("error\n");
		return ret;
	}
	printf("hmacdata\n");
	for (i = 0; i < hmacdatalen; i++) {
		printf("%02x ", hmacdata[i]);
	}
	printf("\nend of hmacdata\n");
	
	return ret;
}