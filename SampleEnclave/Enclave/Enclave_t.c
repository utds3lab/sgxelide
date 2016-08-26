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
	size_t ms_offset;
} ms_init_t;



typedef struct ms_elide_restore_t {
	int ms_retval;
} ms_elide_restore_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_elide_read_file_t {
	char* ms_secret_file;
	uint8_t* ms_buf;
	size_t ms_len;
} ms_elide_read_file_t;

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

static sgx_status_t SGX_CDECL sgx_hello(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	hello();
	return status;
}

static sgx_status_t SGX_CDECL sgx_printSecret(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	printSecret();
	return status;
}

static sgx_status_t SGX_CDECL sgx_elide_restore(void* pms)
{
	ms_elide_restore_t* ms = SGX_CAST(ms_elide_restore_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_elide_restore_t));

	ms->ms_retval = elide_restore();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_init, 0},
		{(void*)(uintptr_t)sgx_hello, 0},
		{(void*)(uintptr_t)sgx_printSecret, 0},
		{(void*)(uintptr_t)sgx_elide_restore, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][4];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL elide_read_file(const char* secret_file, uint8_t* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_secret_file = secret_file ? strlen(secret_file) + 1 : 0;
	size_t _len_buf = len;

	ms_elide_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_elide_read_file_t);
	void *__tmp = NULL;

	ocalloc_size += (secret_file != NULL && sgx_is_within_enclave(secret_file, _len_secret_file)) ? _len_secret_file : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_elide_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_elide_read_file_t));

	if (secret_file != NULL && sgx_is_within_enclave(secret_file, _len_secret_file)) {
		ms->ms_secret_file = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_secret_file);
		memcpy((void*)ms->ms_secret_file, secret_file, _len_secret_file);
	} else if (secret_file == NULL) {
		ms->ms_secret_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);

	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

