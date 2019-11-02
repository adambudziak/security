#include <stdint.h>
#include <typeinfo>
#include <iostream>
#include <string>

#define str(s)  #s
#define xstr(s) str(s)

#define MUL *
#define DIV *
#define ADD +
#define SUB -
#define AND &
#define OR  |
#define XOR ^

#define u64 uint64_t
#define u32 uint32_t
#define f64 double
#define f32 float

void rdtsc() {
  u32 c0, c1;
  __asm__(
    "                 \n\
    cpuid             \n\
    rdtsc             \n\
    mov %%eax,%0      \n\
    mov $0x4000,%%eax \n\
    loop:             \n\
    imul %%r8, %%r9   \n\
    imul %%r9, %%r11  \n\
    sub  $1,%%eax     \n\
    jne loop          \n\
    rdtscp            \n\
    mov %%eax,%1      \n\
    cpuid             \n\
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
  rdtsc();
  return 0;
}