#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<arpa/inet.h>
//int client(int secret_request, uint8_t* buf, size_t len)
int client(const char *secret_request, uint8_t* buf, size_t len)
{
  printf("I am here\n");
  int clientSocket;
  char buffer[1024];
 
  struct sockaddr_in serverAddr;
  socklen_t addr_size;
  
  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);
  
  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(65000);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*---- Connect the socket to the server using the address struct ----*/
  addr_size = sizeof serverAddr;
  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
 
  memcpy(buffer, secret_request, 1);
  printf("request is %s\n", buffer);
  send(clientSocket,buffer,1,0);
 
  printf("send message: %s\n", buffer);
  
  printf("Requesting this much: %d\n",len);
  /*receive the data(meta or data)*/
  size_t amount = recv(clientSocket, buf, len, MSG_WAITALL);
  printf("I received: %d\n",amount);
  printf("meta or data received: %u\n",*buf); 
  printf("meta or data received2: %x\n",*buf); 
  //printf("length: %d\n",len);
  
  return 0;

}

void elide_read_file(const char* secret_name, uint8_t* buf, size_t len){
printf("Reading file %s\n", secret_name);
    FILE *f = fopen(secret_name, "rb");
    
    fread(buf, len, 1, f);
    fclose(f);
}


void elide_server_request(const char* secret_request, uint8_t* buf, size_t len){
    printf("come into the elide_server_request\n");
    client(secret_request, buf, len);
}


