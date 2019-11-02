#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <cstdio>
#include <functional>
using namespace std::placeholders;

void hexdump(uint8_t *p, int n) {
  while (n--) {
    printf("0x%02x,", *p++);
  }
  printf("\n");
}

class client {
  struct sockaddr_in serv_addr;
  int fd;

public:
  client(char *host, int port, uint32_t indx) {
    memset(&serv_addr, '0', sizeof(serv_addr));
    fd = 0;
    struct hostent *he = gethostbyname(host);
    if (!he) {
      printf("err gethostbyname\n");
      return;
    }
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      printf("err socket\n");
      return;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      printf("err connect\n");
      return;
    }
    write((uint8_t *)&indx, sizeof(indx));
    uint32_t clients = 0;
    read((uint8_t *)&clients, sizeof(clients));
    printf("connected clients: %d\n", clients);
  }
  ~client() { exit(); }
  void exit() { close(fd); }
  void write(uint8_t *buf, unsigned size) {
    uint8_t *pos = buf;
    while (size > 0) {
      int ret = ::write(fd, pos, size);
      if (ret <= 0) {
        printf("err write\n");
        exit();
        return;
      }
      pos += ret;
      size -= ret;
    }
  }
  void read(uint8_t *buf, unsigned size) {
    uint8_t *pos = buf;
    while (size > 0) {
      int ret = ::read(fd, pos, size);
      if (ret <= 0) {
        printf("err read\n");
        exit();
        return;
      }
      pos += ret;
      size -= ret;
    }
  }
  void indx(uint32_t idx) { write((uint8_t *)&idx, sizeof(idx)); }
  uint8_t test(uint8_t f, uint8_t *p, unsigned n) {
    // write(&f, sizeof(f));
    write(p, n);
    uint8_t b = 0;
    read(&b, sizeof(b));
    return b;
  }
};

template<typename Fn, typename ...Args>
std::chrono::milliseconds
chck(Fn&& fn, Args&&... args) {
    do {
        auto s = std::chrono::high_resolution_clock::now();
        uint8_t r = fn(args...);
        auto e = std::chrono::high_resolution_clock::now();
        auto t = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
        printf("%s time: %ldms\n", ((r == 1) ? "pass" : "fail"), t);
    } while (0);
}

int main(int argc, char *argv[]) {
  printf("dupa");
  char serv[] = "target.myrelabs.com";
  char *host = serv;
  int port = 7777;
  if (argc > 1) {
    host = argv[1];
  }
  if (argc > 2) {
    port = atoi(argv[2]);
  }
  printf("host:%s\n", host);
  printf("port:%d\n", port);

  /* your index number goes here */
  uint32_t indx = 0x38173;
  client c(host, port, indx);

  uint8_t p0[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  uint8_t p1[] = {0x01, 0x94, 0x7d, 0x62, 0x45, 0x86, 0x34, 0x14, 0x94};
  uint8_t p2[] = {0x02, 0x35, 0x4d, 0x88, 0xe3, 0x33, 0xdd, 0x11, 0x90};
  uint8_t p3[] = {0x03, 0x29, 0x56, 0xd5, 0x4c, 0xb6, 0x0e, 0x0d, 0x0f};
  unsigned n = sizeof(p1);

  // Submit result of this as list solution: */
  printf("index:0x%08x{\n", indx);
  printf("  p0:");
  hexdump(p0, n);
  printf("  p1:");
  hexdump(p1, n);
  printf("  p2:");
  hexdump(p2, n);
  printf("  p3:");
  hexdump(p3, n);
  printf("}\n");

  int counter = 5;
  auto best_time = std::chrono::milliseconds{};

  auto test_fn = std::bind(&client::test, c, _1, _2, _3);

  chck(test_fn, 0, p0, n);
  // int best = 0;
  // for (int i = 0; i < 256; i++) {
  //     p0[1] = static_cast<uint8_t>(i);
  //     chck(test_fn, 0, p0, n);
  // }
  // CHCK(c.test(1, p1, n));
  // CHCK(c.test(2, p2, n));
  // CHCK(c.test(3, p3, n));
  return 0;
}
