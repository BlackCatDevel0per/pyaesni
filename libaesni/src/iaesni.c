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

#include <string.h>
#include <iaesni.h>
#include "iaes_asm_interface.h"

#ifdef _WIN32
    #include <intrin.h> /* __cpuid */
#else
    #include <cpuid.h>
#endif

#if defined(_MSC_VER)
    #ifdef ROUND_KEYS_UNALIGNED_TESTING
        #define DEFINE_ROUND_KEYS                              \
            __declspec(align(16)) UCHAR _expandedKey[16 * 16]; \
            UCHAR *expandedKey = _expandedKey + 4;
    #else
        #define DEFINE_ROUND_KEYS                              \
            __declspec(align(16)) UCHAR _expandedKey[16 * 16]; \
            UCHAR *expandedKey = _expandedKey;
    #endif
#elif defined(__GNUC__) || defined(__clang__) || (defined(__has_attribute) && __has_attribute(aligned))
    #ifdef ROUND_KEYS_UNALIGNED_TESTING
        #define DEFINE_ROUND_KEYS                                     \
            UCHAR __attribute__((aligned(16))) _expandedKey[16 * 16]; \
            UCHAR *expandedKey = _expandedKey + 4;
    #else
        #define DEFINE_ROUND_KEYS                                     \
            UCHAR __attribute__((aligned(16))) _expandedKey[16 * 16]; \
            UCHAR *expandedKey = _expandedKey;
    #endif
#else
    #error "Can't find any align extension"
#endif

#define AES_INSTRUCTIONS_CPUID_BIT (1 << 25)

static void iaesni_cpuid(unsigned int res[4], int leaf) {
#ifdef _WIN32
    __cpuid((int *) res, leaf);
#else
    __cpuid(leaf, res[0], res[1], res[2], res[3]);
#endif
}

/* 
 * check_for_aes_instructions()
 *   return 1 if cpu supports AES-NI, 0 otherwise
 */

int check_for_aes_instructions(void) { /*eax|ebx|ecx|edx*/
    unsigned int cpuid_results[4] = {0, 0, 0, 0};
    /* leaf 0 returns vendor string */
    iaesni_cpuid(cpuid_results, 0);
    /*
     *      MSB         LSB
     * EBX = 'u' 'n' 'e' 'G'
     * EDX = 'I' 'e' 'n' 'i'
     * ECX = 'l' 'e' 't' 'n'
     */

    /* swap 2 and 3 register values to make them appear as EBX EDX ECX */
    {
        unsigned tmp = cpuid_results[2];
        cpuid_results[2] = cpuid_results[3];
        cpuid_results[3] = tmp;
    }

    if (cpuid_results[0] < 1) {
        return 0;
    }
    /* check cpu vendor */
    if (memcmp(&cpuid_results[1], "GenuineIntel", sizeof(*cpuid_results) * 3) != 0 && memcmp(&cpuid_results[1], "AuthenticAMD", sizeof(*cpuid_results) * 3) != 0) {
        return 0;
    }

    /* leaf 1 returns cpu info, ecx contains feature flag we're interested in */
    iaesni_cpuid(cpuid_results, 1);

    if (cpuid_results[2] & AES_INSTRUCTIONS_CPUID_BIT) {
        return 1;
    }

    return 0;
}

void intel_AES_enc128(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;

    iEncExpandKey128(key, expandedKey);
    iEnc128(&aesData);
}

void intel_AES_enc128_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = (UCHAR *) iv;

    iEncExpandKey128(key, expandedKey);
    iEnc128_CBC(&aesData);
}

void intel_AES_enc192(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;

    iEncExpandKey192(key, expandedKey);
    iEnc192(&aesData);
}

void intel_AES_enc192_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = (UCHAR *) iv;

    iEncExpandKey192(key, expandedKey);
    iEnc192_CBC(&aesData);
}

void intel_AES_enc256(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;

    iEncExpandKey256(key, expandedKey);
    iEnc256(&aesData);
}

void intel_AES_enc256_CBC(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = plainText;
    aesData.out_block = cipherText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = (UCHAR *) iv;

    iEncExpandKey256(key, expandedKey);
    iEnc256_CBC(&aesData);
}

void intel_AES_dec128(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;

    iDecExpandKey128(key, expandedKey);
    iDec128(&aesData);
}

void intel_AES_dec128_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, UCHAR *iv, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = iv;

    iDecExpandKey128(key, expandedKey);
    iDec128_CBC(&aesData);
}

void intel_AES_dec192(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;

    iDecExpandKey192(key, expandedKey);
    iDec192(&aesData);
}

void intel_AES_dec192_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, UCHAR *iv, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = iv;

    iDecExpandKey192(key, expandedKey);
    iDec192_CBC(&aesData);
}

void intel_AES_dec256(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;

    iDecExpandKey256(key, expandedKey);
    iDec256(&aesData);
}

void intel_AES_dec256_CBC(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, UCHAR *iv, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = cipherText;
    aesData.out_block = plainText;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = iv;

    iDecExpandKey256(key, expandedKey);
    iDec256_CBC(&aesData);
}

void intel_AES_encdec256_CTR(const UCHAR *input, UCHAR *output, const UCHAR *key, UCHAR *ic, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = input;
    aesData.out_block = output;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = ic;

    iEncExpandKey256(key, expandedKey);
    iEnc256_CTR(&aesData);
}

void intel_AES_encdec192_CTR(const UCHAR *input, UCHAR *output, const UCHAR *key, UCHAR *ic, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = input;
    aesData.out_block = output;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = ic;

    iEncExpandKey192(key, expandedKey);
    iEnc192_CTR(&aesData);
}

void intel_AES_encdec128_CTR(const UCHAR *input, UCHAR *output, const UCHAR *key, UCHAR *ic, size_t numBlocks) {
    DEFINE_ROUND_KEYS
    sAesData aesData;
    aesData.in_block = input;
    aesData.out_block = output;
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = numBlocks;
    aesData.iv = ic;

    iEncExpandKey128(key, expandedKey);
    iEnc128_CTR(&aesData);
}

typedef unsigned long long i_aes_64;
typedef i_aes_64 i_aes_128[2];

static void intel_AES_encdec256_IGE_(const UCHAR *input, UCHAR *output, const UCHAR *key, const UCHAR *iv, size_t numBlocks, int encrypt) {
    DEFINE_ROUND_KEYS
    const i_aes_128 *in  = (const i_aes_128 *) input;
    i_aes_128       *out =       (i_aes_128 *) output;
    i_aes_128 iv1_block, iv2_block;
    ExpandFunc expand_func = (encrypt)
                                 ? iEncExpandKey256
                                 : iDecExpandKey256;
    CryptoFunc crypto_func = (encrypt)
                                 ? iEnc256
                                 : iDec256;
    sAesData aesData;
    expand_func(key, expandedKey);
    aesData.expanded_key = expandedKey;
    aesData.num_blocks = 1;

    memcpy((encrypt) ? iv1_block : iv2_block, iv, sizeof(iv1_block));
    memcpy((encrypt) ? iv2_block : iv1_block, iv + sizeof(iv2_block), sizeof(iv2_block));

    for (size_t i = 0; i < numBlocks; i++, in++, out++) {
        i_aes_128 in_block, out_block, iv2_block_tmp;

        memcpy(in_block, in, sizeof(in_block)); /* this copy is mandatory, `in` can be unaligned */
        iv2_block_tmp[0] = in_block[0];
        iv2_block_tmp[1] = in_block[1];

        in_block[0] ^= iv1_block[0];
        in_block[1] ^= iv1_block[1];

        aesData.in_block = (const UCHAR *) in_block;
        aesData.out_block = (UCHAR *) out_block;
        crypto_func(&aesData);
        out_block[0] ^= iv2_block[0];
        out_block[1] ^= iv2_block[1];
        memcpy(out, out_block, sizeof(out_block));

        iv1_block[0] = out_block[0];
        iv1_block[1] = out_block[1];
        iv2_block[0] = iv2_block_tmp[0];
        iv2_block[1] = iv2_block_tmp[1];
    }
}

void intel_AES_enc256_IGE(const UCHAR *plainText, UCHAR *cipherText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
    intel_AES_encdec256_IGE_(plainText, cipherText, key, iv, numBlocks, 1);
}

void intel_AES_dec256_IGE(const UCHAR *cipherText, UCHAR *plainText, const UCHAR *key, const UCHAR *iv, size_t numBlocks) {
    intel_AES_encdec256_IGE_(cipherText, plainText, key, iv, numBlocks, 0);
}

unsigned long long intel_AES_rdtsc(void) {
    return do_rdtsc();
}
