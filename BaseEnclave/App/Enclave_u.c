#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_elide_restore_t {
	int ms_retval;
} ms_elide_restore_t;

typedef struct ms_elide_read_file_t {
	char* ms_secret_file;
	uint8_t* ms_buf;
	size_t ms_len;
} ms_elide_read_file_t;

static sgx_status_t SGX_CDECL Enclave_elide_read_file(void* pms)
{
	ms_elide_read_file_t* ms = SGX_CAST(ms_elide_read_file_t*, pms);
	elide_read_file((const char*)ms->ms_secret_file, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_elide_read_file,
	}
};
sgx_status_t elide_restore(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_elide_restore_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

