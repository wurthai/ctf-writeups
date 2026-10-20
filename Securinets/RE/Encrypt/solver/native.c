#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <malloc.h>
#include <stdio.h>
#define MS __attribute__((ms_abi))
typedef uint64_t u64;
void* MS ha(u64 h,u64 flags,u64 n){return calloc(1,n?n:32);}
u64 MS hf(u64 h,u64 flags,void*p){free(p);return 1;}
void* MS hr(u64 h,u64 flags,void*p,u64 n){u64 old=malloc_usable_size(p);void*q=realloc(p,n);if(n>old)memset((char*)q+old,0,n-old);return q;}
u64 MS gh(){return 1;}
u64 MS gm(void*name){return 0x140000000;}
void* MS cp(void*a,void*b,u64 n){return memmove(a,b,n);}
void* MS st(void*a,u64 b,u64 n){return memset(a,b,n);}
int MS cmp(void*a,void*b,u64 n){return memcmp(a,b,n);}
void* MS va(void*p,u64 n,u64 typ,u64 prot){return mmap(NULL,(n+4095)&~4095,7,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);}
u64 MS yes(){return 1;}
u64 MS gp(u64 h,char*name){if(!strcmp(name,"VirtualAlloc"))return (u64)va;if(!strcmp(name,"VirtualProtect")||!strcmp(name,"VirtualFree")||!strcmp(name,"FlushInstructionCache"))return (u64)yes;abort();}
int CLEN=90;
int CUSTOM=0;
unsigned char COMPRESSED[65536];
u64 MS compress(u64*out,void*in,u64 n){void*b=calloc(1,CLEN);for(int i=0;i<CLEN;i++)((char*)b)[i]=CUSTOM?COMPRESSED[i]:i;out[0]=CLEN;out[1]=(u64)b;out[2]=CLEN;return(u64)out;}
void encrypt(u64*out,void*in,u64 len,void*params){((void(MS*)(u64*,void*,u64,void*))0x140010110)(out,in,len,params);}
void kdf(void*out,void*in){((void(MS*)(void*,void*))0x140014580)(out,in);}

void master(void*out,u64 env){((void(MS*)(void*,u64))0x14000fdd0)(out,env);}
