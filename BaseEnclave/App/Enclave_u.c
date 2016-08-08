#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_init_t {
	void* ms_bytes;
	size_t ms_len;
	intptr_t ms_offset;
} ms_init_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t init(sgx_enclave_id_t eid, void* bytes, size_t len, intptr_t offset)
{
	sgx_status_t status;
	ms_init_t ms;
	ms.ms_bytes = bytes;
	ms.ms_len = len;
	ms.ms_offset = offset;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

