#ifndef __ORM_H
#define __ORM_H

#include <algorithm>
#include <iostream>
#include <sys/types.h>
#include <cstring>
#include <stdint.h>

class ORMStream
{
public:
  enum { ONLY_SESSION = 1, SESSION_AND_DATA = 2 };
  enum { AUTHED = 0, UN_AUTHED = 1, MONITOR_USER = 2 };
  enum { INTERDICTION = 0, ALLOW = 1 };
  enum state { SESSION_BEGIN = 0, SESSION_END = 1, SESSION_UPDATE = 2 };

  int64_t sid;    // Session ID.
  struct timeval ts;   // Session start time.
  int duration;
  char account[32];
  char mac[12];  // include smac and dmac.
  uint32_t sip;
  uint32_t dip;
  uint16_t sport;
  uint16_t dport;
  int protocol;
  int service;  // 0=other,21=ftp,23=ftp,DB2=50000,1521=Oracle
  short itype;    // ONLY_SESSION = 1, SESSION_AND_DATA = 2
  short eventtype;  // SESSION_BEGIN = 0, SESSION_END = 1, SESSION_UPDATE = 2
  uint32_t bytes;    // bytes count.
  uint32_t records;
  char client[128];  // Client information.
  char server[128];  // Server information.
  int data_len;
  char data[1024];

  ORMStream &copy(const ORMStream &sess) {  // operator =
    if (this == &sess) {
      return *this;
    }

    sid = sess.sid;
    ts.tv_sec = sess.ts.tv_sec;
    ts.tv_usec = sess.ts.tv_usec;
    duration = sess.duration;
    strncpy(account, sess.account, sizeof(account));
    strncpy(mac, sess.mac, sizeof(mac));
    sip = sess.sip;
    dip = sess.dip;
    sport = sess.sport;
    dport = sess.dport;
    protocol = sess.protocol;
    service = sess.service;
    itype = sess.itype;
    eventtype = sess.eventtype;
    bytes = sess.bytes;
    records = sess.records;
    strncpy(client, sess.client, sizeof(client));
    strncpy(server, sess.server, sizeof(server));
    data_len = sess.data_len;
    strncpy(data, sess.data, sizeof(data));
    return *this;
  }

  int length() const {
    return sizeof(ORMStream) - sizeof(data) + std::min(data_len, (int)sizeof(data));
  }
};


/*!
 * @brief TCP transaction.
 */
class ORMTransaction
{
public:
  enum direct { DIRECT_UP = 0, DIRECT_DOWN = 1 };

  int64_t sid;
  struct timeval ts;
  char account[32];
  uint32_t sip;
  uint32_t dip;
  uint16_t sport;
  uint16_t dport;
  int protocol;
  int service;  // 0=other,21=ftp,23=ftp,DB2=50000,1521=Oracle
  uint32_t tcp_seq;
  uint32_t tcp_ack_seq;
  short direct;   //0=up, 1=down
  int seq;
  int duration;
  int data_len;
  char operate[64];
  char object[64];
  char result[64];
  char data[1536];

  ORMTransaction &copy(const ORMTransaction &t) {
    if (this == &t) {
      return *this;
    }

    sid = t.sid;
    ts.tv_sec = t.ts.tv_sec;
    ts.tv_usec = t.ts.tv_usec;
    strncpy(account, t.account, sizeof(account));
    sip = t.sip;
    dip = t.dip;
    sport = t.sport;
    dport = t.dport;
    protocol = t.protocol;
    service = t.service;
    tcp_seq = t.tcp_seq;
    tcp_ack_seq = t.tcp_ack_seq;
    direct = t.direct;
    seq = t.seq;
    duration = t.duration;
    data_len = t.data_len;//yxf add
    strncpy(operate, t.operate, sizeof(operate));
    strncpy(object, t.object, sizeof(object));
    strncpy(result, t.object, sizeof(object));
    strncpy(data, t.data, sizeof(data));
    return *this;
  }

  int length() const {
    return sizeof(ORMTransaction) - sizeof(data) + std::min((int)data_len, (int)sizeof(data));
  }
};


/*!
 * @brief ORM entity. Like ORM header. And has union.
 */
class ORMEntity
{
public:
  enum { STREAM = 1, TRANSACTION = 2, ALARM = 3,
         ORM_HEAD_LEN = 4, MAX_ENTITY_LEN = 2048
       };
  short type;
  short len;
  union {
    ORMStream stream;
    ORMTransaction trans;
  } un;
} ;


/*!
 * @brief class ORM. Include some static functions.
 */
class ORM
{
public:
  ORM() {}
  ~ORM() {}
#if 0
  static int o2r_stream(const ORMStream &s, char *data, int &size);
  static int o2r_transaction(const ORMTransaction &t, char *data, int &size);
#endif
};

std::ostream &operator << (std::ostream &os, const ORMEntity &entity);
std::ostream &operator << (std::ostream &os, const ORMStream &strm);
std::ostream &operator << (std::ostream &os, const ORMTransaction &trans);
#endif

