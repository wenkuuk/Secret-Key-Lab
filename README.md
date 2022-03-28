# Secret-Key-Lab

## Task7 (Python Version)
``` 
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

_, first, second, third = argv

assert len(first) == 21
data = bytearray(first, encoding='utf-8')
ciphertext = bytearray.fromhex(second)
iv = bytearray.fromhex(third)

with open('./WordsList.txt') as f:
    keys = f.readlines()

for k in keys:
    k = k.rstrip('\n')
    if len(k) <= 16:
        key = k + '#'*(16-len(k))
        cipher = AES.new(key=bytearray(key,encoding='utf-8'), mode=AES.MODE_CBC, iv=iv)
        guess = cipher.encrypt(pad(data, 16))
        if guess == ciphertext:
            print("find the key:",key)
            exit(0)

print("cannot find the key!")

``` 
## Task7 (C Version)
```

#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define charMaxLeng 20

//AscToHex()

unsigned char AscToHex(unsigned char Char){
	int aChar = (int)Char;

    if((aChar>=0x30)&&(aChar<=0x39))
        aChar -= 0x30;
    else if((aChar>=0x41)&&(aChar<=0x46))//大写字母
        aChar -= 0x37;
    else if((aChar>=0x61)&&(aChar<=0x66))//小写字母
        aChar -= 0x57;
    else 
        aChar = 0xff;

    return aChar;
}

//HexToAsc()

unsigned char HexToAsc(unsigned char aHex){
    if((aHex>=0)&&(aHex<=9))
        aHex += 0x30;
    else if((aHex>=10)&&(aHex<=15))//A-F
        aHex += 0x37;
    else 
        aHex = 0xff;

    return aHex;
}

unsigned char* str2hex(char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    // printf("%d \n", str_len);
    // printf("%s\n", str);
    assert((str_len%2) == 0);
    ret = (char *)malloc(str_len/2);
    for (i =0;i < str_len; i = i+2 ) {
        sscanf(str+i,"%2hhx",&ret[i/2]);
    }
    return ret;
}


char *padding_buf(char *buf,int size, int *final_size) {
    char *ret = NULL;
    int pidding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;

    *final_size = size + pidding_size;
    ret = (char *)malloc(size+pidding_size);
    memcpy( ret, buf, size);
    if (pidding_size!=0) {
        for (i =size;i < (size+pidding_size); i++ ) {
            ret[i] = pidding_size;
        }
    }

    return ret;
}

void printf_buff(char *buff,int size) {
    int i = 0;
    for (i=0;i<size;i ++ ) {
        // printf( "%02X ", (unsigned char)buff[i] );
		printf( "%02X", (unsigned char)buff[i] );
        if ((i+1) % 8 == 0) {
            // printf("\n");
        }
    }

    printf("\n");
}

void encrpyt_buf(char *raw_buf, char **encrpy_buf, int len, char* kkey) {
    AES_KEY aes;
    unsigned char *key = str2hex(kkey);
    unsigned char *iv = str2hex("aabbccddeeff00998877665544332211");
    AES_set_encrypt_key(key,128,&aes);
    AES_cbc_encrypt(raw_buf,*encrpy_buf,len,&aes,iv,AES_ENCRYPT);

    free(key);
    free(iv);
}

void decrpyt_buf(char *raw_buf, char **encrpy_buf, int len, char* kkey) {
    AES_KEY aes;
    unsigned char *key = str2hex(kkey);
    unsigned char *iv = str2hex("aabbccddeeff00998877665544332211");
    AES_set_decrypt_key(key,128,&aes);
    AES_cbc_encrypt(raw_buf,*encrpy_buf,len,&aes,iv,AES_DECRYPT);

    free(key);
    free(iv);
}

int main(int argc, char* argv[]) {
	char* target="764AA26B55A4DA654DF6B19E4BCE00F4ED05E09346FB0E762583CB7DA2AC93A2";
	FILE* p=NULL;
	if((p=fopen("words.txt","r"))==NULL)  //以只读的方式打开test。
	{
		printf("ERROR");		
	}

	char buffer[charMaxLeng];
	char buf2[charMaxLeng];
	int flag=0;

	while (!feof(p)){
		int i=0;
		memset(buffer,'\0', charMaxLeng * sizeof(char));
		memset(buf2,'\0', charMaxLeng * sizeof(char));
		fgets(buffer, charMaxLeng, p);
		while(i<charMaxLeng){
			buf2[i]=buffer[i];
			i+=1;
		}
		size_t len = strlen(buffer);
		if (len == 1)	continue;
		// printf("%s", buffer);
		

	    char *raw_buf = NULL;
	    char *after_padding_buf = NULL;
	    int padding_size = 0;
	    char *encrypt_buf = NULL;
	    char *decrypt_buf = NULL;

	    i=0;
	    unsigned char* key=NULL;
	    key=(unsigned char*)malloc(33);

	    while(i < strlen(buffer)){
	    	unsigned char letter = buffer[i];
	    	
	    	key[2*i] = HexToAsc(letter/0x10);
	    	key[2*i+1] = HexToAsc(letter%0x10);
	    	// printf("%d\n", i);

	    	++i;
	    	if(i==0x0f || buffer[i] < 0x20)
	    		break;
	    }
	    while(i < 0x10){
	    	key[2*i] = '2';
	    	key[2*i+1] = '3';
	    	++i;
	    }
	    key[0x20]='\0';
	    // printf("%s\n", key);
	    raw_buf = (char *)malloc(21);
	    memcpy(raw_buf,"This is a top secret.",21);
	    after_padding_buf = padding_buf(raw_buf,21,&padding_size);

	    encrypt_buf = (char *)malloc(padding_size);
	    encrpyt_buf(after_padding_buf,&encrypt_buf, padding_size, key);
	    
	    // printf("%d\n", strlen(target));
	    i=0;
	    char temp='\0';
	    flag=1;
	    while(i<padding_size){
	    	temp = HexToAsc((unsigned char)encrypt_buf[i]/0x10);
	    	if(temp!=target[2*i]){
	    		flag=0;
	    		break;
			}
	    	temp = HexToAsc((unsigned char)encrypt_buf[i]%0x10);
	    	if(temp!=target[2*i+1]){
	    		flag=0;
	    		break;
			}
	    	i+=1;
	    }
	    if(flag==0){
	   		continue;
		}
		printf("%s", buf2);
		printf_buff(encrypt_buf,padding_size);
		printf("%s\n", target);

	    free(raw_buf);
	    free(after_padding_buf);
	    free(encrypt_buf);
	    free(decrypt_buf);
	    // printf("%02X\n", (unsigned char)('T'));
	    break;
	}
    fclose(p);
    return 0;
}

```
