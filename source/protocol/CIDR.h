#ifndef __CIDR_H
#define __CIDR_H

#include <string>
#include <stdint.h>

/*!
 * @brief The class defines declares CIDR function.
 */
class CIDR
{
protected:
  CIDR() {};
  ~CIDR() {};

public:
  static int cidr2addr(const std::string &cidr, uint32_t &ip, uint32_t &mask);
  static int cidr2addr(const char *cidr, uint32_t &ip, uint32_t &mask);

  static int addr2cidr(uint32_t ip, uint32_t mask, std::string &cidr);
  static int addr2cidr(uint32_t ip, uint32_t mask, char *cidr, uint32_t len);

  // It is the same with inet_ntoa, but not use it any more.
  // use static varible, and not thread safe.
  static const std::string &ntoa(uint32_t ip);
  static const char *ntos(uint32_t ip);

  // not use static varible, but thread safe.
  static const std::string &ntoa(uint32_t ip, std::string &addr);
  static const char *ntos(uint32_t ip, char *addr, int size);

  // mac address to string. and reverse.
  static const char *mac2str(const uint8_t *mac, char *buf, int len);
  static const uint8_t *str2mac(const char *buf, uint8_t *mac);

protected:
  static std::string a_addr_;
  static char s_addr_[20];
};

#endif	//__CIDR_H

