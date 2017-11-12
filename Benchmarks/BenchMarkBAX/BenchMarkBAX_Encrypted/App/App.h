#include <stdint.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif
void init_enclave(void);

void bridge_init_store();

void bridge_free_store();

void bridge_add_to_store(const void *bytes, size_t len);

void bridge_get_from_store(uint8_t *out_var,size_t len,uint16_t index);

void bridge_encrypt_store(const char * fname);

void bridge_decrypt_store(uint8_t *ebytes, size_t len);
#if defined(__cplusplus)
}
#endif
