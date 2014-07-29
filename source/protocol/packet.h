#ifndef _PACKET_H
#define _PACKET_H
#include <stdint.h>

const static int ETHER_ADDR_LEN = 6;
#ifndef __BYTE_ORDER
#define __BYTE_ORDER 1234
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#endif
#define IPVERSION 4
#define MAXTTL 255

#ifndef TCP_CLOSED
#define TCP_CLOSED 0
#define TCP_SYN_RCVD 1
#define TCP_SYN_SENT 2
#define TCP_ESTABLISHED 3
#define TCP_CLOSING 4
#endif

struct ether_header {
  uint8_t ether_dhost[ETHER_ADDR_LEN];
  uint8_t ether_shost[ETHER_ADDR_LEN];
  uint16_t ether_type;
};

struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint32_t ihl: 4;
  uint32_t version: 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint32_t version: 4;
  uint32_t ihl: 4;
#endif
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /*The options start here. */
};

struct tcphdr {
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint16_t res1: 4;
  uint16_t doff: 4;
  uint16_t fin: 1;
  uint16_t syn: 1;
  uint16_t rst: 1;
  uint16_t psh: 1;
  uint16_t ack: 1;
  uint16_t urg: 1;
  uint16_t res2: 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint16_t doff: 4;
  uint16_t res1: 4;
  uint16_t res2: 2;
  uint16_t urg: 1;
  uint16_t ack: 1;
  uint16_t psh: 1;
  uint16_t rst: 1;
  uint16_t syn: 1;
  uint16_t fin: 1;
#endif
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};

struct udphdr {
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};


#endif
