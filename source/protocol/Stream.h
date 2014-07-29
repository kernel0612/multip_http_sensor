#ifndef __STREAM_H
#define __STREAM_H

#include <iostream>
#include "Orm.h"
#include "Frame.h"
#include <stdint.h>
#ifndef _WIN32
#include <sys/time.h>
#endif


/*!
 * @brief This structure defines tcp stream key. As you know they are four value:
 * source address, destination address, source port and destination port.
 */
class StreamKey
{
public:
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;

  int copy(const FrameHdr &framehdr);
  int copy(const Frame &frame);
  StreamKey &reverse();

  struct hash {
    size_t operator()(const StreamKey &key) const {
      uint32_t __h = 0;

      for (size_t i = 0; i < sizeof(StreamKey); i++) {
        __h = 5 * __h + size_t(((char *)&key) + i) ;
      }

      return size_t(__h);
    }
  };

  struct equal {
    bool operator()(const StreamKey &k1, const StreamKey &k2) const {
      return (k1.saddr == k2.saddr && k1.daddr == k2.daddr && \
              k1.sport == k2.sport && k1.dport == k2.dport) || \
             (k1.daddr == k2.saddr && k1.saddr == k2.daddr && \
              k1.dport == k2.sport && k1.sport == k2.dport);
    }
  };

  /*
   * memcmp is good. the other two will cause loop for ever when being reversed.
   */
  bool operator < (const StreamKey &k2) const {
    return memcmp(this, &k2, sizeof(StreamKey)) < 0;
  }

  bool operator == (const StreamKey &k2) const {
    return (saddr == k2.saddr && daddr == k2.daddr && sport == k2.sport && \
            dport == k2.dport) || (daddr == k2.saddr && saddr == k2.daddr && \
                                   dport == k2.sport && sport == k2.dport);
  }

} ;

/*!
 * @brief This structure defines tcp stream peer key. As you know they are four value:
 * address and port.
 */
class PeerKey
{
public:
  uint32_t addr;
  uint16_t port;

  PeerKey(uint32_t a, uint16_t p) : addr(a), port(p) {}
  bool operator < (const PeerKey &k2) const {
    return memcmp(this, &k2, sizeof(PeerKey)) < 0;
  }

  bool operator == (const PeerKey &k2) const {
    return addr == k2.addr && port == k2.port;
  }
};

/*!
 * @brief This structure defines IP subnet. Means address and mask.
 */
//class Subnet
//{
//public:
//  uint32_t addr;
//  uint32_t mask;
//
//  Subnet(uint32_t a, uint32_t m) : addr(a), mask(m) {}
//
//  bool operator == (const Subnet &sub) const {
//    return sub.addr == addr && sub.mask == mask;
//  }
//};


/*!
 * @brief This structure defines tcp stream, also called tcp session.
 */
class Stream
{
public:
  StreamKey key;
  char mac[12];	// include smac and dmac.

  //! stream begin time.
  struct timeval begin;
  time_t live;		// Live or Active time.

  int service;	// Service.
  uint32_t seq;
  uint32_t ack_seq;

  short stat;		// TCP status.
  short flag;		// TCP Flag. Such as repeat frame. 0 = N/A, 1 = Duplicate frame.

  //! Follow about stream functions.
  int64_t	sid;
  int devid;
  int rid;		// Rule ID. Also means policy ID.
  char account[32];

  uint32_t bytes;		// TCP data bytes.
  uint32_t packets;	// TCP total up ip packets.
  uint32_t records;	// TCP total records number to audit.

  char client[128];	// Client information.
  char server[128];	// Server information.
  //char summary_[1024];
  char response[1536];	// response from server.
  char *private_data; //yxf add
  ORMTransaction trans;			// Transactions on this stream.
  void response2transaction(ORMTransaction &t);
  void stream2orm(ORMStream &s) const;
} ;

std::ostream &operator << (std::ostream &os, const StreamKey &key);
std::ostream &operator << (std::ostream &os, const PeerKey &key);

#endif //__STREAM_H

