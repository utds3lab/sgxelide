#include "sgx_tcrypto.h"
#include <stddef.h>

typedef struct sgx_CryptStore_CryptData {
	const sgx_aes_gcm_128bit_key_t *p_key;//Encryption key
	const uint8_t *p_iv;//Initialization vector
} sgx_CryptStore_CryptData;

typedef struct sgx_CryptStore_Store {
	uint16_t header_len;
	uint32_t *offsets;
	uint32_t body_len;
	uint8_t *entries;
} sgx_CryptStore_Store;

sgx_CryptStore_Store *sgx_CryptStore_allocStore();
void sgx_CryptStore_freeStore(sgx_CryptStore_Store *store);

sgx_CryptStore_CryptData *sgx_CryptStore_allocCryptData(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_iv);
void sgx_CryptStore_freeCryptData(sgx_CryptStore_CryptData * data);

uint16_t sgx_CryptStore_add(sgx_CryptStore_Store *store, void *data, size_t size);
uint8_t sgx_CryptStore_get(sgx_CryptStore_Store *store, size_t index, void *out_var);

uint8_t* sgx_CryptStore_toBytes(sgx_CryptStore_Store *store, size_t *len);
void sgx_CryptStore_fromBytes(sgx_CryptStore_Store *store, uint8_t* bytes);

uint8_t* sgx_CryptStore_encrypt(sgx_CryptStore_CryptData *data, sgx_CryptStore_Store *store, size_t *len);
sgx_status_t sgx_CryptStore_decrypt(sgx_CryptStore_CryptData *data, sgx_CryptStore_Store *store, uint8_t* ebytes, size_t len);
