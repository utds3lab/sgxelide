#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_init_t {
	void* ms_bytes;
	size_t ms_len;
	size_t ms_offset;
} ms_init_t;


typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
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

