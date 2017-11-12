//#include "Enclave.h"
#include "Enclave_t.h"
#include <stdlib.h>
#include <string.h>

#define ANSWER "Evilzone"

extern void printf(const char *fmt, ...);

void nope()
{
  ocall_puts_string("Nope.");
  //puts("Nope.");
  //exit(1);
  ocall_exit(1);
}

void good()
{
  ocall_puts_string("Good job.");
  //puts("Good job.");
}

int crackme()
{
  int r, i, c;
  char converted[9], input[24], check[4];
  printf("Please enter the secret number: ");
  ocall_scanf_string(&r,"%23s", input);
  printf("I read in %s\n",input);
  //r = scanf("%23s", input);
  if (1 != r)
      nope();
if ('9' != input[1])
      nope();
  if ('6' != input[0])
      nope();
  //fflush(stdin);
  ocall_fflush_string();
  memset(converted, 0, sizeof converted);
  converted[0] = 'E';
  check[3] = '\0';
  for (i = 2, c = 1; strlen(converted) < 8 && i < strlen(input); i += 3, c++) {
      check[0] = input[i];
      check[1] = input[i+1];
      check[2] = input[i+2];
      converted[c] = atoi(check);
  }
  converted[c] = '\0';
  if (strcmp(converted, ANSWER) == 0) {
      printf("The Password translates into %s, ", converted);
      good();
  }
  else
      nope();
  return 0;
}

