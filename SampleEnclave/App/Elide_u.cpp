#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

void elide_read_file(const char* secret_name, uint8_t* buf, size_t len){
printf("Reading file %s\n", secret_name);
    FILE *f = fopen(secret_name, "rb");
    
    fread(buf, len, 1, f);
    fclose(f);
}
