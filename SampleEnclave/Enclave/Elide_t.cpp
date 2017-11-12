//#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "sgx_tcrypto.h"

#include <string.h>
#include <stdlib.h>

#define REQUEST_META 0
#define REQUEST_DATA 1

#define ERROR_GET_META_FAILED 1
#define ERROR_GET_DATA_FAILED 2
#define ERROR_DECRYPT_FAILED 3

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
			}else if( index > 2 && meta->encrypted){	//Read key, iv, and tag
				//These fields will only be populated if encrypted is 1
				memcpy(meta->key, buf+i+1, 16);
				memcpy(meta->iv,  buf+i+1+16, 12);
				memcpy(meta->tag, buf+i+1+16+12, 16);
				break;
			}
			index++;
		}
	}
	//printf("%d,%d,%d\n",meta->offset, meta->length, meta->encrypted);
	//printhex(meta->key,16);
	//printhex(meta->iv,12);
	//printhex(meta->tag,16);
	//printf("%x\n",*(meta->key));
	//printf("%x\n",*(meta->iv));
	//printf("%x\n",*(meta->tag));
	return 0;
}

int _elide_server_request(int type, void* result, void* extra){
        const sgx_aes_gcm_128bit_key_t key[] = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'};
        const uint8_t iv[] = {'1','2','3','4','5','6','7','8','9','0','1','2'};
	sgx_status_t sgx_ecode;
	uint8_t buf[84];
	uint8_t buffer[64];
	uint8_t tag[16];
	uint8_t decrypted[64];
	
	uint32_t length;
	//printf("I am in the _elide_server_request\n");
	if( type ==  REQUEST_META ){
		elide_server_request("0", buf, 84);
		length = *((uint32_t*)buf);
		memcpy(tag, buf+4, 16);
		//printf("First byte of tag: %x\n", tag);
		memcpy(buffer, buf+20, length);
		//printf("length is %u\n", length);
		//printf("tag is %x\n", tag);
		//printf("ct is %x\n", buffer);
		if( sgx_ecode = sgx_rijndael128GCM_decrypt(key, (const uint8_t* )buffer,length,decrypted,iv,12,NULL,0,(const sgx_aes_gcm_128bit_tag_t*)tag) ){
		//printf("ERROR CODE: %d\n", sgx_ecode);
		return sgx_ecode;
	}
		//elide_read_file("enclave.secret.meta",buf,64);
		elide_meta* meta = (elide_meta*)result;
		_elide_parse_meta(meta, decrypted, length);		
	}else if( type == REQUEST_DATA ){
		uint8_t buffer_data[((elide_meta*)extra)->length + 20];
		uint8_t buf_data[((elide_meta*)extra)->length];
		elide_server_request("1", buffer_data, (((elide_meta*)extra)->length+20));
		//printf("lenght of ((elide_meta*)extra)->length: %u\n", ((elide_meta*)extra)->length);
                length = *((uint32_t*)buffer_data);
		//printf("Length: %u\n", length);
		memcpy(tag, buffer_data+4, 16);
		//printf("First bytes of message: ");
		for( int q = 0; q < 32; q++ ){
			//printf("%02x",*(buffer_data+q));
		}
		//printf("\n");
		//printf("First byte of tag: %x\n", *tag);
		memcpy(buf_data, buffer_data+20, length);
		//printf("length is %u\n", length);
		//printf("tag is %x\n", tag);
		//printf("ct is %x\n", buf_data);
		if( sgx_ecode = sgx_rijndael128GCM_decrypt(key,(const uint8_t* )buf_data,length,(uint8_t*)result,iv,12,NULL,0,(const sgx_aes_gcm_128bit_tag_t*)tag) ){
		//printf("ERROR CODE: %d\n", sgx_ecode);
		return sgx_ecode;
	}
		//elide_read_file(elide_secret_file, (uint8_t*)result, ((elide_meta*)extra)->length);
	}
	return 0;
}

int _elide_get_meta(elide_meta* meta){
	return _elide_server_request(REQUEST_META, meta, NULL);
}

int _elide_get_bytes(elide_meta* meta, uint8_t* bytes){
	if( meta->encrypted ){
		elide_read_file(elide_secret_file, bytes, meta->length);
	}else{
		return _elide_server_request(REQUEST_DATA, bytes, meta);
	}
	return 0;
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
	//printf("elide_restore\n");
	//elide_server_connect();
        //elide_server_attest();
	elide_meta meta;
	sgx_status_t sgx_ecode;
	if( _elide_get_meta(&meta) ){
		return ERROR_GET_META_FAILED;
	}
	uint8_t* bytes = (uint8_t*)malloc(meta.length);//If this is unencrypted length this will not work TODO: figure it out
        //printf("sercer side\n");
	if(int q = _elide_get_bytes(&meta, bytes) ){
		return q;//ERROR_GET_DATA_FAILED;
	}
	if( meta.encrypted ){
		uint8_t* dbytes = (uint8_t*)malloc(meta.length);
		if(sgx_ecode= _elide_decrypt_bytes( bytes, meta.length, dbytes, &(meta.key), (const uint8_t*)&(meta.iv), 12, &(meta.tag) ) ){
			return sgx_ecode;
		}
		void *start = (uint8_t*)&elide_restore-meta.offset;
        	memmove(start, dbytes, meta.length);
	}else{
		void *start = (uint8_t*)&elide_restore-meta.offset;
        	memmove(start, bytes, meta.length);
	}
	return 0;
}

