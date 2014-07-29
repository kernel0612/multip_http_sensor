#ifndef __FRAME_H
#define __FRAME_H

#include <iostream>
#include <sys/time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "packet.h"

/*!
 * @brief This structure defines frame.
 */

class FrameHdr;
class Frame
{
public:
  enum { FRAME_HEAD_LEN = 12, ETH_HEAD_LEN = 14, VLAN_HEAD_LEN = 4, ETH_DATA_LEN = 1500 };
  enum {
    ETH_P_IP	= 0x0800,	/* Internet Protocol packet	*/
    ETH_P_ARP	= 0x0806,	/* Address Resolution packet	*/
    ETH_P_8021Q	= 0x8100	/* 802.1Q VLAN Extended Header  */
  };
  Frame() {}
  virtual ~Frame() {}

  //! frame captured time. Detail int micro seconds.
  struct timeval ts;

  //! actual captured frame length.
  uint32_t caplen;

  //! buffer for frame.
  uint8_t pkt[ETH_HEAD_LEN + 2 + ETH_DATA_LEN];

  //! frame equel function.
  Frame &operator= (const Frame &f);

  //! copy from libpcap structure.
  int copy(const struct pcap_pkthdr &pkth, const uint8_t *pkt);

  //! copy from frame header structure.
  int copy(const FrameHdr &framehdr);

  //! get IP header.
  inline const struct iphdr *iphdr() const {
    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      return (struct iphdr *)(pkt + 14);
    }

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      return (struct iphdr *)(pkt + 14 + 4);
    }

    return NULL;
  }

  //! static get IP header from packet.
  static inline struct iphdr *iphdr(const uint8_t *p) {
    if (ntohs(*(uint16_t *)(p + 12)) == 0x0800) {	// ETH_P_IP
      return (struct iphdr *)(p + 14);
    }

    if (ntohs(*(uint16_t *)(p + 12)) == 0x8100) {	// ETH_P_8021Q
      return (struct iphdr *)(p + 14 + 4);
    }

    return NULL;
  }

  //! get TCP header.
  inline const struct tcphdr *tcphdr() const {
    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      return pkt[14 + 9] != 6 ? NULL : (struct tcphdr *)(pkt + 14 + (pkt[14] & 0x0F) * 4);
    }

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      return pkt[14 + 4 + 9] != 6 ? NULL : (struct tcphdr *)(pkt + 14 + 4 + (pkt[14 + 4] & 0x0F) * 4);
    }

    return NULL;
  }

  //! get UDP header.
  inline const struct udphdr *udphdr() const {
    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      return pkt[14 + 9] != 17 ? NULL : (struct udphdr *)(pkt + 14 + (pkt[14] & 0x0F) * 4);
    }

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      return pkt[14 + 4 + 9] != 17 ? NULL : (struct udphdr *)(pkt + 14 + 4 + (pkt[14 + 4] & 0x0F) * 4);
    }

    return NULL;
  }

  //! get TCP or UDP payload.
  inline const uint8_t *payload() const {
    int ethhlen, iphlen, tcphlen;

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      ethhlen = 14;
    } else if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      ethhlen = 14 + 4;
    } else {
      return NULL;
    }

    iphlen = (pkt[ethhlen] & 0x0F) * 4;

    if (pkt[ethhlen + 9] == 6) {
      tcphlen = (pkt[ethhlen + iphlen + 12] >> 4) * 4;
    } else if (pkt[ethhlen + 9] == 17) {
      tcphlen = 8;  //sizeof(struct udphdr);
    } else {
      return NULL;
    }

    return pkt + ethhlen + iphlen + tcphlen;
  }

  //! get tcp or udp payload.
  inline int payload(const char **data) const {
    int ethhlen, iphlen, tcphlen;

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      ethhlen = 14;
    } else if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      ethhlen = 14 + 4;
    } else {
      return 0;
    }

    iphlen = (pkt[ethhlen] & 0x0F) * 4;

    if (pkt[ethhlen + 9] == 6) {
      tcphlen = (pkt[ethhlen + iphlen + 12] >> 4) * 4;
    } else if (pkt[ethhlen + 9] == 17) {
      tcphlen = 8;
    } else {
      return 0;
    }

    *data = (char *)pkt + ethhlen + iphlen + tcphlen;
    return caplen - ethhlen - iphlen - tcphlen;
  }

} ;

/*!
 * @brief This structure defines frame header. Just include ETH, IP and TCP header.
 */
class FrameHdr
{
public:
  FrameHdr() {}
  virtual ~FrameHdr() {}
  //! frame captured time. Detail int micro seconds.
  struct timeval ts;

  //! actual captured frame length.
  uint32_t caplen;

  //! buffer for frame. Set to 96 bytes, should include ETH, IP and TCP header.
  uint8_t pkt[96];

  //! frame equel function.
  FrameHdr &operator= (const FrameHdr &f);

  //! copy from libpcap structure.
  int copy(const struct pcap_pkthdr &pkth, const uint8_t *pkt);

  //! get IP header.
  inline const struct iphdr *iphdr() const {
    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      return (struct iphdr *)(pkt + 14);
    }

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      return (struct iphdr *)(pkt + 14 + 4);
    }

    return NULL;
  }

  //! get TCP header.
  inline const struct tcphdr *tcphdr() const {
    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x0800) {	// ETH_P_IP
      return pkt[14 + 9] != 6 ? NULL : (struct tcphdr *)(pkt + 14 + (pkt[14] & 0x0F) * 4);
    }

    if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
      return pkt[14 + 4 + 9] != 6 ? NULL : (struct tcphdr *)(pkt + 14 + 4 + (pkt[14 + 4] & 0x0F) * 4);
    }

    return NULL;
  }

  //! Dump frame information in one line.
  char *dump(char *buf, int len) const;

} ;

/*!
 * @brief This structure defines sniffer frame header. Include device id ahd length of frame.
 */
//typedef struct sniffer_hdr {
//  uint16_t device;
//  uint16_t len;
//} Sniffer_Hdr;

std::ostream &operator << (std::ostream &os, const Frame &frm);

#endif //__FRAME_H

