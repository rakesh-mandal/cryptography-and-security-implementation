#include <stdio.h>
#include <time.h>
#include "mldsa.h"
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
int main(void){
  int lv[3]={44,65,87};
  for(int a=0;a<3;a++){int L=lv[a];uint8_t pk[MLDSA_MAX_PK_BYTES],sk[MLDSA_MAX_SK_BYTES],sig[MLDSA_MAX_SIG_BYTES],m[32]={1};size_t sl;
    int n=200;double t=now();for(int i=0;i<n;i++)mldsa_keygen(L,pk,sk);double kg=(now()-t)/n;
    t=now();for(int i=0;i<n;i++){m[0]=i;mldsa_sign(L,sig,&sl,m,32,0,0,sk,0);}double sg=(now()-t)/n;
    t=now();for(int i=0;i<n;i++)mldsa_verify(L,sig,sl,m,32,0,0,pk);double vf=(now()-t)/n;
    printf("ML-DSA-%d: keygen %.0f us, sign %.0f us, verify %.0f us\n",L,kg*1e6,sg*1e6,vf*1e6);}
}
