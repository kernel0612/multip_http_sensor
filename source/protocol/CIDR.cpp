#include "CIDR.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

std::string CIDR::a_addr_ = "";
char CIDR::s_addr_[20] = {0};

int CIDR::cidr2addr(const std::string &cidr, uint32_t &ip, uint32_t &mask)
{
  volatile int i = 0;

  if ((i = cidr.find('/')) == (int)std::string::npos) {
    return -1;
  }

  uint32_t addr = inet_addr(cidr.substr(0, i).c_str());

  if (addr == INADDR_NONE) {
    return -1;
  }

  ip = addr;
  int masklen = atoi(cidr.substr(i + 1).c_str());

  if (masklen == 0) {
    mask = 0;
  } else if (masklen > 0 && masklen <= 32) {
    mask = htonl(0xFFFFFFFF << (32 - masklen));
  } else {
    mask = 0xFFFFFFFF;
  }

  ip = (ip & mask);
  return 0;
}

int CIDR::cidr2addr(const char *cidr, uint32_t &ip, uint32_t &mask)
{
  char tmp[32] = {0};
  strncpy(tmp, cidr, sizeof(tmp) - 1);
  char *p = strchr(tmp, '/');

  if (p == NULL) {
    uint32_t addr = inet_addr(tmp);

    if (addr == INADDR_NONE) {
      return -1;
    }

    ip = addr;
    mask = 0xFFFFFFFF;
    return 0;
  }

  *p++ = '\0';
  uint32_t addr = inet_addr(tmp);

  if (addr == INADDR_NONE) {
    return -1;
  }

  ip = addr;
  int masklen = atoi(p);

  if (masklen == 0) {
    mask = 0;
  } else if (masklen > 0 && masklen <= 32) {
    mask = htonl(0xFFFFFFFF << (32 - masklen));
  } else {
    mask = 0xFFFFFFFF;
  }

  ip = (ip & mask);
  return 0;
}

int CIDR::addr2cidr(uint32_t ip, uint32_t mask, std::string &cidr)
{
  volatile uint32_t i = 0;
  uint32_t imask = ntohl(mask);

  // 32 is the uint32_teger's bits length.
  for (i = 0; i < 32; i++)
    if (!((imask << i) & 0x80000000)) {
      break;
    }

  std::string addr = "";
  CIDR::ntoa(ip & mask, addr);
  cidr = addr;
  char tmp[16] = {0};
#ifdef WIN32
  _snprintf(tmp, sizeof(tmp), "/%d", i);
#else
  snprintf(tmp, sizeof(tmp), "/%d", i);
#endif
  cidr += tmp;
  return 0;
}

int CIDR::addr2cidr(uint32_t ip, uint32_t mask, char *cidr, uint32_t len)
{
  volatile uint32_t i = 0;
  uint32_t imask = ntohl(mask);

  // 32 is the uint32_teger's bits length.
  for (i = 0; i < 32; i++)
    if (!((imask << i) & 0x80000000)) {
      break;
    }

  char tmp[20] = {0};
  CIDR::ntos(ip & mask, tmp, sizeof(tmp) - 1);
  strncpy(cidr, tmp, len - 1);
#ifdef WIN32
  _snprintf(tmp, sizeof(tmp), "/%d", i);
#else
  snprintf(tmp, sizeof(tmp), "/%d", i);
#endif
  strncat(cidr, tmp, len - strlen(cidr));
  return 0;
}

const std::string &CIDR::ntoa(uint32_t ip)
{
  return CIDR::a_addr_ = CIDR::ntos(ip, CIDR::s_addr_, sizeof(CIDR::s_addr_));
}

const std::string &CIDR::ntoa(uint32_t ip, std::string &addr)
{
  char tmp_addr[20] = {0};
  return addr = CIDR::ntos(ip, tmp_addr, sizeof(tmp_addr));
}

const char *CIDR::ntos(uint32_t ip)
{
  char addr[20] = {'\0'};
  CIDR::ntos(ip, addr, sizeof(CIDR::s_addr_));
  return strdup(addr);
}

const char *CIDR::ntos(uint32_t ip, char *addr, int size)
{
  uint8_t *p = (uint8_t *)&ip;
#ifdef WIN32
  _snprintf(addr, size, "%d.%d.%d.%d", \
            (int)p[0], (int)p[1], (int)p[2], (int)p[3]);
#else
  snprintf(addr, size, "%d.%d.%d.%d", \
           (int)p[0], (int)p[1], (int)p[2], (int)p[3]);
#endif
  return addr;
}

const char *CIDR::mac2str(const uint8_t *mac, char *buf, int len)
{
  buf[len - 1] = '\0';
  snprintf(buf, len - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

const uint8_t *CIDR::str2mac(const char *buf, uint8_t *mac)
{
  return mac;
}

