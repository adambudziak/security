#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <stdint.h>
#include <inttypes.h>
#include <chrono>
#include <iostream>
void hexdump(uint8_t *p, int n) {
  while(n--){
    printf("0x%02x,",*p++);
  }
  printf("\n");
}
class client {
  struct sockaddr_in serv_addr; 
  int fd;
public:
  client(char *host, int port, uint32_t indx) {
    memset(&serv_addr,'0',sizeof(serv_addr));
    fd = 0;
    struct hostent *he = gethostbyname(host);
    if(!he) {
      printf("err gethostbyname\n");
      return;
    }
    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
      printf("err socket\n");
      return;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port); 
    memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    if(connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
      printf("err connect\n");
      return;
    }
    write((uint8_t*)&indx, sizeof(indx));
    uint32_t clients = 0;
    read((uint8_t*)&clients, sizeof(clients));
    printf("connected clients: %d\n", clients);
  }
  ~client() {
    exit();
  }
  void exit() {
    close(fd);
  }
  void write(uint8_t *buf, unsigned size) {
    uint8_t *pos = buf;
    while(size>0) {
      int ret = ::write(fd,pos,size);
      if(ret<=0) {
        printf("err write\n");
        exit();
        return;
      }
      pos  += ret;
      size -= ret;
    }
  }
  void read(uint8_t *buf, unsigned size) {
    uint8_t *pos = buf;
    while(size>0) {
      int ret = ::read(fd,pos,size);
      if(ret<=0) {
        printf("err read\n");
        exit();
        return;
      }
      pos  += ret;
      size -= ret;
    }
  }
  void indx(uint32_t idx) {
    write((uint8_t*)&idx, sizeof(idx));
  }
  uint8_t test(uint8_t f, uint8_t *p, unsigned n) {
    //write(&f, sizeof(f));
    write(p,  n);
    uint8_t b = 0;
    read (&b, sizeof(b));
    return b;
  }
};
#define CHCK(f) \
do { \
  auto s = std::chrono::high_resolution_clock::now(); \
  uint8_t r = f; \
  auto e = std::chrono::high_resolution_clock::now(); \
  auto t = std::chrono::duration_cast<std::chrono::milliseconds>(e-s).count(); \
  printf("%s time: %ldms\n", ((r==1)?"pass":"fail"), t);\
} while(0)
int main(int argc, char *argv[]) {
  char serv[] = "target.myrelabs.com";
  char *host  = serv;
  int   port  = 7777;
  if(argc > 1) {
    host = argv[1];
  }
  if(argc > 2){
    port = atoi(argv[2]);
  }
  printf("host:%s\n",host);
  printf("port:%d\n",port);
  
  /* your index number goes here */
  uint32_t indx = 229747; 
  client c(host,port,indx);
  // Budziax: p0 \x0c\xae\x13\xb3\xa3Ib\xab
  //          p1 \xcde\xb3\xb3\xe6V5\xdb
  //          p2 's\x19\xee&\x96n\xfb\xd2 
  // Kondziu: p3  mRi\xa8\xcb\xf5\x0e\x0c
  // Kondziu: p0  \x03\xa8\xee\xa6]\x99\xa8\x19

  uint8_t p0[] = {0x00,0x0c,0xae,0x13,0xb3,0xa3, 'I', 'b',0xab};
  uint8_t p1[] = {0x01,0xcd, 'e',0xb3,0xb3,0xe6, 'V', '5',0xdb};
  uint8_t p2[] = {0x02, 's',0x19,0xee, '&',0x96, 'n',0xfb,0xd2};
  uint8_t p3[] = {0x03,0x99,0xc0,0xcd,0x54,0x72,0x68,0x27,0x27};
  unsigned n = sizeof(p1);
  
  /* Submit result of this as list solution: */
  printf("index:0x%08x{\n",indx);
  printf("  p0:");hexdump(p0,n);
  printf("  p1:");hexdump(p1,n);
  printf("  p2:");hexdump(p2,n);
  printf("  p3:");hexdump(p3,n);
  printf("}\n");
  
  CHCK(c.test(0,p0,n));
  CHCK(c.test(1,p1,n));
  CHCK(c.test(2,p2,n));
  CHCK(c.test(3,p3,n));
  return 0;
}
