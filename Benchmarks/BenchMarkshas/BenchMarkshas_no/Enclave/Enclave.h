/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

#include "sgx_tcrypto.h"

/* If this is not defined as a static const, gcc will complain that it causes a section type conflict */
//intptr_t _encrypted_section_offset = 0xDEADDEADDEADDEAD;
const void* _encrypted_section_start;
const void* _encrypted_section_end;

#if defined(__cplusplus)
extern "C" {
#endif
#include "sha.h"
#include "sha-private.h"
int SHA1Reset(SHA1Context *context);
int SHA224Reset(SHA224Context *context);
int SHA256Reset(SHA256Context *context);
int SHA384Reset(SHA384Context *context);

int SHA512Reset(SHA512Context *context);

int hmacReset(HMACContext *ctx, enum SHAversion whichSha,
    const unsigned char *key, int key_len);

int hmacInput(HMACContext *ctx, const unsigned char *text,
    int text_len);

int hmacFinalBits(HMACContext *ctx,
    const uint8_t bits,
    unsigned int bitcount);
int hmacResult(HMACContext *ctx, uint8_t *digest);
int USHAReset(USHAContext *ctx, enum SHAversion whichSha);
int USHAInput(USHAContext *ctx,
              const uint8_t *bytes, unsigned int bytecount);
int USHAFinalBits(USHAContext *ctx,
                  const uint8_t bits, unsigned int bitcount);
int USHAResult(USHAContext *ctx,
               uint8_t Message_Digest[USHAMaxHashSize]);

void printf(const char *fmt, ...); 

void decrypt_section();

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
