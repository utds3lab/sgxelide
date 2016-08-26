#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, elide_read_file, (const char* secret_file, uint8_t* buf, size_t len));

sgx_status_t init(sgx_enclave_id_t eid, void* bytes, size_t len, size_t offset);
sgx_status_t hello(sgx_enclave_id_t eid);
sgx_status_t printSecret(sgx_enclave_id_t eid);
sgx_status_t elide_restore(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
