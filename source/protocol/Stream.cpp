#include "Stream.h"
#include "Frame.h"
#include "CIDR.h"
#include "packet.h"


int StreamKey::copy(const FrameHdr &framehdr)
{
  const struct iphdr *iph = framehdr.iphdr();
  const struct tcphdr *tcph = framehdr.tcphdr();

  if (tcph == NULL) {
    return -1;
  }

  saddr = iph->saddr;
  daddr = iph->daddr;
  sport = tcph->source;
  dport = tcph->dest;
  return 0;
}

int StreamKey::copy(const Frame &frame)
{
  const struct iphdr *iph = frame.iphdr();
  const struct tcphdr *tcph = frame.tcphdr();

  if (tcph == NULL) {
    return -1;
  }

  saddr = iph->saddr;
  daddr = iph->daddr;
  sport = tcph->source;
  dport = tcph->dest;
  return 0;
}

StreamKey &StreamKey::reverse()
{
  uint32_t tmpi = saddr;
  saddr = daddr;
  daddr = tmpi;
  uint16_t tmps = sport;
  sport = dport;
  dport = tmps;
  return *this;
}

void Stream::response2transaction(ORMTransaction &t)
{
  t.sid = sid;
  memcpy(&t.ts, &trans.ts, sizeof(struct timeval));
  t.direct = ORMTransaction::DIRECT_DOWN;
  t.seq = trans.seq;
  t.data_len = strlen(response);
  memset(t.operate, 0, sizeof(t.operate));
  memset(t.object, 0, sizeof(t.object));
  memset(t.result, 0, sizeof(t.result));
  memcpy(t.data, response, t.data_len);
}

void Stream::stream2orm(ORMStream &s) const
{
  s.sid = sid;
  memcpy(&s.ts, &begin, sizeof(struct timeval));
  s.duration = live - begin.tv_sec;
  strncpy(s.account, account, sizeof(s.account));
  memcpy(s.mac, mac, sizeof(s.mac));
  s.sip = key.saddr;
  s.dip = key.daddr;
  s.sport = key.sport;
  s.dport = key.dport;
  s.protocol = 6;		// TCP
  s.service = service;
  s.bytes = bytes;
  s.records = records;
  strncpy(s.client, client, sizeof(s.client));
  strncpy(s.server, server, sizeof(s.server));
  s.data_len = 0;
}

std::ostream &operator << (std::ostream &os, const StreamKey &key)
{
  os << CIDR::ntos(key.saddr) << ":" << ntohs(key.sport);
  return os << "->" << CIDR::ntos(key.daddr) << ":" << ntohs(key.dport);
}

std::ostream &operator << (std::ostream &os, const PeerKey &key)
{
  return os << CIDR::ntos(key.addr) << ":" << ntohs(key.port);
}

