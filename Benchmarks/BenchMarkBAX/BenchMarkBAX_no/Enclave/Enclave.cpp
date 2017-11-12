#include "Enclave_t.h"

#include "sgx_trts.h"
#include "CryptStore.c"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */


#if defined(__cplusplus)
extern "C" {
#endif
void init_store();
void init_store();
void free_store();
void add_to_store(const void *bytes, size_t len);
void get_from_store(void *out_var, size_t len, size_t index);
void encrypt_store(const char *fname);
void decrypt_store(const uint8_t *ebytes, size_t len);
void store_to_bytes();
#if defined(__cplusplus)
}
#endif
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

sgx_CryptStore_Store *store;


void init_store(){
	store = sgx_CryptStore_allocStore();
}

void free_store(){
	sgx_CryptStore_freeStore(store);
}

void add_to_store(const void *bytes, size_t len){
	sgx_CryptStore_add(store,(void *)bytes,len);
}

//len is needed for sgx to know the number of bytes to copy
void get_from_store(void *out_var, size_t len, size_t index){
	sgx_CryptStore_get(store, index, out_var);
}

void encrypt_store(const char* fname){
	const sgx_aes_gcm_128bit_key_t key[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	const uint8_t iv[] = {1,2,3,4,5,6,7,8,9,10,11,12};
	sgx_CryptStore_CryptData *data = sgx_CryptStore_allocCryptData((sgx_aes_gcm_128bit_key_t *)&key,(uint8_t *)&iv);

	size_t outLen;
	uint8_t *ebytes = sgx_CryptStore_encrypt(data,store,&outLen);
	sgx_CryptStore_freeCryptData(data);

	//printf("Encrypting store with size %u\n", outLen);
	ocall_write_resource(fname, ebytes, outLen);

	free(ebytes);
}

void decrypt_store(const uint8_t *ebytes, size_t len){
	const sgx_aes_gcm_128bit_key_t key[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	const uint8_t iv[] = {1,2,3,4,5,6,7,8,9,10,11,12};
	sgx_CryptStore_CryptData *data = sgx_CryptStore_allocCryptData((sgx_aes_gcm_128bit_key_t *)&key,(uint8_t *)&iv);

	//printf("Decrypting store with size %u\n", len);
	sgx_status_t stat = sgx_CryptStore_decrypt(data,store,(uint8_t *)ebytes,len);
	
	//printf("ERROR %x\n", stat);
}

void store_to_bytes(){
	size_t len;
	uint8_t *bytes = sgx_CryptStore_toBytes(store,&len);

	ocall_print_raw(bytes,len);
	free(bytes);
}
