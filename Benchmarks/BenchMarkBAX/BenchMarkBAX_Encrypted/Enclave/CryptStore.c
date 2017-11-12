#include "CryptStore.h"
#include <stdlib.h>
#include <string.h>

sgx_CryptStore_Store *sgx_CryptStore_allocStore(){
	sgx_CryptStore_Store *retval = (sgx_CryptStore_Store *) malloc(sizeof(sgx_CryptStore_Store));
	retval->header_len = 0;
	retval->offsets = (uint32_t *) malloc(sizeof(uint32_t));//Allocate size of one header entry
	retval->body_len = 0;
	retval->entries = (uint8_t *) malloc(sizeof(uint8_t));//Allocate size of one byte
	return retval;
}
void sgx_CryptStore_freeStore(sgx_CryptStore_Store *store){
	free(store->offsets);
	free(store->entries);
	free(store);
}

sgx_CryptStore_CryptData *sgx_CryptStore_allocCryptData(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_iv){
	sgx_CryptStore_CryptData *retval = (sgx_CryptStore_CryptData *) malloc(sizeof(sgx_CryptStore_CryptData));
	retval->p_key = p_key;
	retval->p_iv = p_iv;
	return retval;
}
void sgx_CryptStore_freeCryptData(sgx_CryptStore_CryptData * data){
	free(data);
}

uint16_t sgx_CryptStore_add(sgx_CryptStore_Store *store, void *data, size_t size){
	store->offsets = (uint32_t *) realloc(store->offsets,sizeof(uint32_t)*(store->header_len+1));//Allocate only exactly what we need
	store->offsets[store->header_len] = store->body_len;//Declare offset of this entry is at the current body length
	store->header_len++;//One more header entry has been added

	store->entries = (uint8_t *) realloc(store->entries, sizeof(uint8_t)*store->body_len+sizeof(uint8_t)*size);//Allocate size of new entry
	memcpy(store->entries+store->body_len,data,size);//Copy bytes into allocated space
	store->body_len += sizeof(uint8_t)*size;//Update length

	return store->header_len-1;
}
/* Returns 1 on success, 0 on an out of bounds index */
uint8_t sgx_CryptStore_get(sgx_CryptStore_Store *store, size_t index, void *out_var){
	size_t size;//Apparently the C standard in use prevents moving size after the if statement.
	//Apparently MSVC supports C90 (ANSI C).  Surprise!
	if( (index >= store->header_len || index < 0) ){
		return 0;
	}
	size = index == store->header_len-1 ?
		sizeof(uint8_t)*(store->body_len - store->offsets[index]) :
		sizeof(uint8_t)*(store->offsets[index+1] - store->offsets[index]);
	memcpy(out_var,store->entries+store->offsets[index], size);//size using size_t allows (2^32)-1 length or offset (on this platform)
	return 1;
}

uint8_t* sgx_CryptStore_toBytes(sgx_CryptStore_Store *store, size_t *len){
	size_t header_len_size = sizeof(store->header_len);
	size_t header_size = store->header_len*sizeof(*store->offsets);
	size_t body_len_size = sizeof(store->body_len);
	size_t body_size = store->body_len*sizeof(*store->entries);
	size_t store_size = header_len_size+header_size+body_len_size+body_size;
	size_t copied_size = 0;
	uint8_t *bytes = (uint8_t *) malloc(store_size);

	memcpy(bytes,&store->header_len,header_len_size);
	copied_size+=header_len_size;

	memcpy(bytes+copied_size,store->offsets,header_size);
	copied_size+=header_size;

	memcpy(bytes+copied_size,&store->body_len,body_len_size);
	copied_size+=body_len_size;

	memcpy(bytes+copied_size,store->entries,body_size);

	*len = store_size;
	return bytes;
}
void sgx_CryptStore_fromBytes(sgx_CryptStore_Store *store, uint8_t* bytes){
	size_t header_size;
	store->header_len =  *((uint16_t *)bytes);//An error here defererenced a byte ptr and THEN cast it as a two-byte int, losing info
	header_size = store->header_len*sizeof(*store->offsets);
	store->offsets = (uint32_t *) realloc(store->offsets, header_size);
	memcpy(store->offsets, bytes+sizeof(store->header_len), header_size);
	store->body_len =  *((uint32_t *)(bytes+sizeof(store->header_len)+header_size));
	store->entries = (uint8_t *) realloc(store->entries, store->body_len);//Since it's in bytes, body_len should be equivalent
	memcpy(store->entries, bytes+sizeof(store->header_len)+header_size+sizeof(store->body_len), store->body_len);
}

/* Returns NULL on failure */
uint8_t* sgx_CryptStore_encrypt(sgx_CryptStore_CryptData *data, sgx_CryptStore_Store *store, size_t *len){
	size_t bsize;
	uint8_t *bytes = sgx_CryptStore_toBytes(store,&bsize);
	//16 byte block size, adding an extra block should always be enough?
	//I don't understand why, but the encrypted data seems to always match the exact length of
	//the original data.  It does NOT snap to any block size!  Why?
	//Therefore, we won't add the extra 16 to allow for correct block size!
	//We keep the other 16 for the appended 128-bit GCM MAC
	uint8_t *ebytes = (uint8_t *) malloc(bsize+16);
	//IV size of 12 as recommended by NIST
	sgx_status_t stat = sgx_rijndael128GCM_encrypt(data->p_key,bytes,bsize,ebytes,data->p_iv,12,NULL,0,(sgx_aes_gcm_128bit_tag_t *)(ebytes+bsize));
	free(bytes);
	if( stat != SGX_SUCCESS ){
		free(ebytes);
		return NULL;
	}
	*len = bsize+16;//Full size of all bytes, including appended MAC
	return ebytes;
}
/* Returns SGX_SUCCESS on success, and the error returned from decryption on decryption error */
sgx_status_t sgx_CryptStore_decrypt(sgx_CryptStore_CryptData *data, sgx_CryptStore_Store *store, uint8_t* ebytes, size_t len){
	uint8_t *bytes = (uint8_t *) malloc(len-16);//Take off length allocated for MAC
	sgx_status_t stat = sgx_rijndael128GCM_decrypt(data->p_key,ebytes,len-16,bytes,data->p_iv,12,NULL,0,(sgx_aes_gcm_128bit_tag_t *)(ebytes+len-16));
	if( stat != SGX_SUCCESS ){
		free(bytes);
		return stat;
	}
	sgx_CryptStore_fromBytes(store,bytes);
	free(bytes);
	return SGX_SUCCESS;
}
