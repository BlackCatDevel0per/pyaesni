#include <iaesni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test vectors based on NIST Recommendation for Block Cipher Modes of Operation 
// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
unsigned char test_plain_text[64] =   {	0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
										0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
										0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
										0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};

unsigned char test_key_256[32] =      {	0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
										0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};

unsigned char test_init_vector[16] =  {	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

unsigned char test_cipher_256_cbc[64]={ 0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,
										0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d,
										0x39,0xf2,0x33,0x69,0xa9,0xd9,0xba,0xcf,0xa5,0x30,0xe2,0x63,0x04,0x23,0x14,0x61,
										0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b};

void printhex(const unsigned char *s, size_t size){
    for (const unsigned char *end = s + size; s < end; s++) {
        printf("%x", *s);
    }
    putchar('\n');
}

void test_cbc_256(){
	unsigned int buffer_size = 64;
	int nbocks = 4;
	unsigned int i;
	unsigned char *testVector = malloc(buffer_size);
	unsigned char *testResult = malloc(buffer_size);
	unsigned char test_iv[16];

	for (i=0;i<buffer_size;i++)
	{
		testVector[i] = test_plain_text[i];
		testResult[i] = 0xee;
	}

	memcpy(test_iv, test_init_vector, 16);
	
	printf("IV value before the call: ");
    printhex(test_iv, sizeof(test_iv));
	enc_256_CBC(testVector, testResult, test_key_256, test_iv, nbocks);
	printf("IV value after the call: ");
    printhex(test_iv, sizeof(test_iv));
	
	for (i=0;i<buffer_size;i++)
	{
		if (testResult[i] != test_cipher_256_cbc[i])
		{	
			printf("AES-CBC-256 Encryption Failed\n");
		}
	}
	
	memcpy(test_iv,test_init_vector,16);
	dec_256_CBC(testResult,testVector,test_key_256, test_iv, nbocks);

	for (i=0;i<buffer_size;i++)
	{
		if (testVector[i] != test_plain_text[i])
		{
			printf("AES-CBC-256 Decryption Failed\n");
		}
	}

	printf("AES-CBC-256 Successful\n");
    free(testVector);
    free(testResult);
}

int main(){
	int AES_ENABLED = check_for_aes_instructions();
	if (AES_ENABLED == 1){
		printf ("The CPU supports AES-NI\n");
		test_cbc_256();
        return EXIT_SUCCESS;
	}
	else{
		printf ("The CPU seems to not support AES-NI\n");
		return EXIT_FAILURE;
	}
}
