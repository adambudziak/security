#include <stdint.h>
#include <typeinfo>
#include <iostream>
#include <string>

#define u64 uint64_t
#define u32 uint32_t

void rdtsc() {
  u32 c0, c1;
  
  
  __asm__(
    "               \n\
    xor %%rax,%%rax \n\
    rdtsc           \n\
    mov %%eax,%0    \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    nop             \n\
    rdtsc           \n\
    mov %%eax,%1    \n\
    "
    : "=r"(c0),"=r"(c1)
    : 
    : "rax","rcx","rdx","r8","r9","r10","r11","r12"
  );
  std::cout << __FUNCTION__        << "\n"
            << "  c0:   " << c0    << "\n" 
            << "  c1:   " << c1    << "\n"
            << "  diff: " << c1-c0 << "\n";
}

uint64_t n = 32*1024*1024;
int main(int argc, char *argv[]) {
  int i = 100;
  while(i --> 0) {
    rdtsc();
  }
  return 0;
}
