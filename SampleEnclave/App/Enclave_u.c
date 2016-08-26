#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_elide_read_file(void* pms)
{
	ms_elide_read_file_t* ms = SGX_CAST(ms_elide_read_file_t*, pms);
	elide_read_file((const char*)ms->ms_secret_file, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_elide_read_file,
	}
};
sgx_status_t init(sgx_enclave_id_t eid, void* bytes, size_t len, size_t offset)
{
	sgx_status_t status;
	ms_init_t ms;
	ms.ms_bytes = bytes;
	ms.ms_len = len;
	ms.ms_offset = offset;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t hello(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t printSecret(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t elide_restore(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_elide_restore_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

