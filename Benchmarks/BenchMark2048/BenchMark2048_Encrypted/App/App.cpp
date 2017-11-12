#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <errno.h>
#include <time.h>

struct timespec diff(struct timespec start, struct timespec end)
{
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

//#define ENCLAVE_FILE "..\\Debug\\Enclave1.signed.dll"
# define ENCLAVE_FILE "enclave.signed.so"
#define MAX_BUF_LEN  100


//For some reason this doesn't match the linkage specification,
//EVEN THOUGH IT MATCHES EXACTLY.
//I had to delete the definition of this in the header file...
void ocall_write_resource(const char *str, const void *bytes, size_t len){
	FILE *outfile = fopen(str,"wb");
	fwrite(&len,sizeof(len),1,outfile);
	fwrite(bytes, sizeof(uint8_t), len, outfile);
	fclose(outfile);
}

void ocall_write_out(const void *bytes, size_t len){
	FILE *outfile = fopen("blob.txt","wb");
	fwrite(&len,sizeof(len),1,outfile);
	fwrite(bytes, sizeof(uint8_t), len, outfile);
	fclose(outfile);
}

void ocall_print_raw(const void *bytes, size_t len){
	FILE *outfile = fopen("raw_bytes.txt","wb");
	fwrite(&len,sizeof(len),1,outfile);
	fwrite(bytes, sizeof(uint8_t), len, outfile);
	fclose(outfile);
	/*uint8_t *b = (uint8_t *)bytes;
	for( int i = 0; i < len; i++ ){
		printf("%u",b[i]);
	}*/
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}



sgx_enclave_id_t eid;

sgx_enclave_id_t createEnclave()
{
	//int i;

	sgx_enclave_id_t   eid;
	sgx_status_t       ret   = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int testingdebugval = SGX_DEBUG_FLAG;
	int updated = 0;
	struct timespec time1, time2;
	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, 
							 &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		//cin  >> i;
		return -1;
	}
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time1);
	 int res;
        elide_restore(eid, &res);
        printf("Error code %d\n", res);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time2);

	printf("Time elapsed in enclave initialization: %d seconds, %d nanoseconds\n", diff(time1,time2).tv_sec, diff(time1,time2).tv_nsec );
	return eid;
}
	
int destroyEnclave(sgx_enclave_id_t eid){
	// Destroy the enclave when all Enclave calls finished.
	if(SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}

void init_enclave(void){
	eid = createEnclave();
}

void bridge_init_store(){
	init_store(eid);
}

void bridge_free_store(){
	free_store(eid);
}

void bridge_add_to_store(const void *bytes, size_t len){
	add_to_store(eid,bytes,len);
}

void bridge_get_from_store(uint8_t *out_var,size_t len,size_t index){
	//store_to_bytes(eid);//TEMP: TODO REMOVE
	get_from_store(eid,out_var,len,index);
}

void bridge_encrypt_store(const char* fname){
	encrypt_store(eid, fname);
}

void bridge_decrypt_store(uint8_t *ebytes, size_t len){
	decrypt_store(eid,ebytes,len);
}

/*void enclave_pack_res(char *name, uint8_t *bytes, size_t len){
	printf("Furious %d", eid);
	pack_resource(eid,name,bytes,len);
}*/

/*void main(int argc, char *argv[]){
	sgx_enclave_id_t eid = createEnclave();
	//testOutside();
	foo(eid);
}*/
