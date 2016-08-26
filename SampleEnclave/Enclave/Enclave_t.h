#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void init(void* bytes, size_t len, size_t offset);
void hello();
void printSecret();
int elide_restore();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL elide_read_file(const char* secret_file, uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
