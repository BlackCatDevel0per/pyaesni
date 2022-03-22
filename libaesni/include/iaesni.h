/* 
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors 
 *       may be used to endorse or promote products derived from this software 
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
*/

/* 2016, Amirali Sanatinia (amirali@ccs.neu.edu) */

#ifndef IAESNI_H
#define IAESNI_H

#include <libaesni_export.h>
#include <stdlib.h>

/* indicates input param */
#define IAES_IN

/* indicates output param */
#define IAES_OUT

/* indicates input/output param - based on context */
#define IAES_INOUT

#define IAES_BLOCK_SIZE  16 /*in bytes*/
#define IAES_128_KEYSIZE 16 /*in bytes*/
#define IAES_192_KEYSIZE 24 /*in bytes*/
#define IAES_256_KEYSIZE 32 /*in bytes*/

typedef unsigned char UCHAR;

#ifdef __cplusplus
extern "C" {
#endif

/* test if the processor actually supports the above functions */
/* executing one the functions below without processor support will cause UD fault */
/* bool check_for_aes_instructions(void); */
LIBAESNI_EXPORT int check_for_aes_instructions(void);

/* encryption functions */
/* plainText is pointer to input stream */
/* cipherText is pointer to buffer to be filled with encrypted (cipher text) data */
/* key is pointer to enc key (sizes are 16 bytes for AES-128, 24 bytes for AES-192, 32 for AES-256) */
/* numBlocks is number of 16 bytes blocks to process - note that encryption is done of full 16 byte blocks */
LIBAESNI_EXPORT void intel_AES_enc128(IAES_IN const UCHAR *plainText, IAES_OUT UCHAR *cipherText, IAES_IN const UCHAR key[IAES_128_KEYSIZE], IAES_IN size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_enc192(IAES_IN const UCHAR *plainText, IAES_OUT UCHAR *cipherText, IAES_IN const UCHAR key[IAES_192_KEYSIZE], IAES_IN size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_enc256(IAES_IN const UCHAR *plainText, IAES_OUT UCHAR *cipherText, IAES_IN const UCHAR key[IAES_256_KEYSIZE], IAES_IN size_t numBlocks);

LIBAESNI_EXPORT void intel_AES_enc256_IGE(const UCHAR *plainText, UCHAR *cipherText, const UCHAR key[IAES_256_KEYSIZE], const UCHAR iv[2 * IAES_BLOCK_SIZE], size_t numBlocks);

LIBAESNI_EXPORT void intel_AES_enc128_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR key[IAES_128_KEYSIZE], const UCHAR iv[IAES_BLOCK_SIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_enc192_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR key[IAES_192_KEYSIZE], const UCHAR iv[IAES_BLOCK_SIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_enc256_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR key[IAES_256_KEYSIZE], const UCHAR iv[IAES_BLOCK_SIZE], size_t numBlocks);

/* encryption functions */
/* cipherText is pointer to encrypted stream */
/* plainText is pointer to buffer to be filled with original (plain text) data */
/* key is pointer to enc key (sizes are 16 bytes for AES-128, 24 bytes for AES-192, 32 for AES-256) */
/* numBlocks is number of 16 bytes blocks to process - note that decryption is done of full 16 byte blocks */
LIBAESNI_EXPORT void intel_AES_dec128(IAES_IN const UCHAR *cipherText, IAES_OUT UCHAR *plainText, IAES_IN const UCHAR key[IAES_128_KEYSIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_dec192(IAES_IN const UCHAR *cipherText, IAES_OUT UCHAR *plainText, IAES_IN const UCHAR key[IAES_192_KEYSIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_dec256(IAES_IN const UCHAR *cipherText, IAES_OUT UCHAR *plainText, IAES_IN const UCHAR key[IAES_256_KEYSIZE], size_t numBlocks);

LIBAESNI_EXPORT void intel_AES_dec256_IGE(const UCHAR *cipherText, UCHAR *plainText, const UCHAR key[IAES_256_KEYSIZE], const UCHAR iv[2 * IAES_BLOCK_SIZE], size_t numBlocks);

LIBAESNI_EXPORT void intel_AES_dec128_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR key[IAES_128_KEYSIZE], IAES_INOUT UCHAR iv[IAES_BLOCK_SIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_dec192_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR key[IAES_192_KEYSIZE], IAES_INOUT UCHAR iv[IAES_BLOCK_SIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_dec256_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR key[IAES_256_KEYSIZE], IAES_INOUT UCHAR iv[IAES_BLOCK_SIZE], size_t numBlocks);

LIBAESNI_EXPORT void intel_AES_encdec128_CTR(const UCHAR *input, UCHAR *output, const UCHAR key[IAES_128_KEYSIZE], IAES_INOUT UCHAR ic[IAES_BLOCK_SIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_encdec192_CTR(const UCHAR *input, UCHAR *output, const UCHAR key[IAES_192_KEYSIZE], IAES_INOUT UCHAR ic[IAES_BLOCK_SIZE], size_t numBlocks);
LIBAESNI_EXPORT void intel_AES_encdec256_CTR(const UCHAR *input, UCHAR *output, const UCHAR key[IAES_256_KEYSIZE], IAES_INOUT UCHAR ic[IAES_BLOCK_SIZE], size_t numBlocks);

LIBAESNI_EXPORT unsigned long long intel_AES_rdtsc(void);

#ifdef __cplusplus
}
#endif

#endif /* IAESNI_H */
