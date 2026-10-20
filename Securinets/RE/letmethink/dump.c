#define _GNU_SOURCE
#include <link.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
static void dump(void *vm) {
 int f=open("analysis/vmstate.bin",O_CREAT|O_TRUNC|O_WRONLY,0600);write(f,vm,0x20080);close(f);
 uintptr_t *v=(uintptr_t*)((char*)vm+0x20010);
 f=open("analysis/bytecode.bin",O_CREAT|O_TRUNC|O_WRONLY,0600);write(f,(void*)v[0],v[1]);close(f);_exit(0);
}
__attribute__((naked)) static void hook(){ __asm__("mov 0x168(%rsp),%rdi; and $-16,%rsp; call dump;"); }
static int cb(struct dl_phdr_info *i,size_t s,void*x){
 if(!i->dlpi_name[0]){unsigned char*p=(void*)(i->dlpi_addr+0xf70c78);mprotect((void*)((uintptr_t)p&~4095UL),4096,7);p[0]=0xff;p[1]=0x25;*(int*)(p+2)=0;*(uintptr_t*)(p+6)=(uintptr_t)hook;}
 return 0;
}
__attribute__((constructor))static void init(){dl_iterate_phdr(cb,0);}
