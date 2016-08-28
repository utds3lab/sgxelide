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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "sgx_tcrypto.h"

#include <string.h>

#define REQUEST_META 0
#define REQUEST_DATA 1

#define ERROR_GET_META_FAILED 1
#define ERROR_GET_DATA_FAILED 2
#define ERROR_DECRYPT_FAILED 3
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void printhex(uint8_t* buf, size_t len){
	printf("0x");
	for( int i = 0; i < len; i++){
		printf("%x",*(buf+i));
	}
	printf("\n");
}
/*
char elide_secret_file[] = "enclave.secret.dat";

typedef struct {
	intptr_t offset;
	size_t length;
        uint8_t encrypted;
	sgx_aes_gcm_128bit_key_t key;
	uint8_t iv[12];
	sgx_aes_gcm_128bit_tag_t tag;
} elide_meta; 

int _elide_parse_meta(elide_meta* meta, uint8_t* buf, size_t len){
	meta->offset = atol((const char*) buf);
	int index = 1;
	for( int i = 0; i < len; i++ ){
		if( buf[i] == '\n' ){
			if( index == 1 ){	//Read length
				meta->length = atol((const char*) (buf+i));
			}else if( index == 2 ){	//Read encrypted bool
				meta->encrypted = buf[i+1]-'0';
			}else{	//Read key, iv, and tag
				memcpy(meta->key, buf+i+1, 16);
				memcpy(meta->iv,  buf+i+1+16, 12);
				memcpy(meta->tag, buf+i+1+16+12, 16);
				break;
			}
			index++;
		}
	}
	return 0;
	//printf("%d,%d,%d\n",meta->offset, meta->length, meta->encrypted);
	//printhex(meta->key,16);
	//printhex(meta->iv,12);
	//printhex(meta->tag,16);
	//printf("%x\n",*(meta->key));
	//printf("%x\n",*(meta->iv));
	//printf("%x\n",*(meta->tag));
}

int _elide_server_request(int type, void* result){
	if( type ==  REQUEST_META ){
		//This is NOT what the final version will do:
		//TODO: communicate with server
		uint8_t buf[64];
		elide_read_file("enclave.secret.meta",buf,64);
		elide_meta* meta = (elide_meta*)result;
		_elide_parse_meta(meta, buf, 64);		
	}else{
		//UNIMPLEMENTED
		return -1;
	}
}

int _elide_get_meta(elide_meta* meta){
	return _elide_server_request(REQUEST_META, meta);
}

int _elide_get_bytes(elide_meta* meta, uint8_t* bytes){
	if( meta->encrypted ){
		elide_read_file(elide_secret_file, bytes, meta->length);
	}else{
		//UNIMPLEMENTED
		return -1;	
	}
}

sgx_status_t _elide_decrypt_bytes(const uint8_t* encrypted, uint32_t encrypted_len, uint8_t* decrypted, const sgx_aes_gcm_128bit_key_t* key, const uint8_t iv[12], uint32_t iv_len, const sgx_aes_gcm_128bit_tag_t* tag){
	sgx_status_t sgx_ecode;
	if( sgx_ecode = sgx_rijndael128GCM_decrypt(key,encrypted,encrypted_len,decrypted,iv,12,NULL,0,tag) ){
		//printf("ERROR CODE: %d\n", sgx_ecode);
		return sgx_ecode;
	}
        return SGX_SUCCESS;
}

int elide_restore(){
	//elide_server_connect();
        //elide_server_attest();
	elide_meta meta;
	if( _elide_get_meta(&meta) ){
		return ERROR_GET_META_FAILED;
	}
	uint8_t* bytes = (uint8_t*)malloc(meta.length);//If this is unencrypted length this will not work TODO: figure it out
	if( _elide_get_bytes(&meta, bytes) ){
		return ERROR_GET_DATA_FAILED;
	}
	if( meta.encrypted ){
		uint8_t* dbytes = (uint8_t*)malloc(meta.length);
		if( _elide_decrypt_bytes( bytes, meta.length, dbytes, &(meta.key), (const uint8_t*)&(meta.iv), 12, &(meta.tag) ) ){
			return ERROR_DECRYPT_FAILED;
		}
		void *start = (uint8_t*)&elide_restore-meta.offset;
        	memmove(start, dbytes, meta.length);
	}else{
		//void *start = (uint8_t*)&init-offset;
        	//memmove(start, bytes, len);
	}
	return 0;
}
*/
