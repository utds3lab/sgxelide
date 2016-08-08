#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_init_t {
	void* ms_bytes;
	size_t ms_len;
	intptr_t ms_offset;
} ms_init_t;

static sgx_status_t SGX_CDECL sgx_init(void* pms)
{
	ms_init_t* ms = SGX_CAST(ms_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_bytes = ms->ms_bytes;
	size_t _tmp_len = ms->ms_len;
	size_t _len_bytes = _tmp_len;
	void* _in_bytes = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_init_t));
	CHECK_UNIQUE_POINTER(_tmp_bytes, _len_bytes);

	if (_tmp_bytes != NULL) {
		_in_bytes = (void*)malloc(_len_bytes);
		if (_in_bytes == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_bytes, _tmp_bytes, _len_bytes);
	}
	init(_in_bytes, _tmp_len, ms->ms_offset);
err:
	if (_in_bytes) free(_in_bytes);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_init, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


