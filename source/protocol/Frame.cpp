#include "Frame.h"
#include "CIDR.h"
#include <algorithm>
#include <iostream>
#include "packet.h"
#include <cstring>
#include <cassert>
#include <ace/Log_Msg.h>

#include <pcap.h>

/*!
 * Load config items from config file or some else.
 * @param f another frame.
 * @return the frame itself.
 */
Frame &Frame::operator= (const Frame &f)
{
  if (this == &f) {
    return *this;
  }

  int length = FRAME_HEAD_LEN + (f.caplen < sizeof(this->pkt) ? f.caplen : sizeof(this->pkt));
  caplen = f.caplen;
  ts = f.ts;
  memcpy(pkt, f.pkt, length);
  return *this;
}

/*!
 * parse the tcp payload after the tcp header into a pointer.
 * ingore the tcp without payload.
 * ingore vlan tag.
 * @return payload length on success or < 0 on error.
 */
int Frame::copy(const struct pcap_pkthdr &pkth, const uint8_t *pkt)
{
  const struct iphdr *iph = NULL;
  const struct tcphdr *tcph = NULL;
  const struct ether_header *ethhdr =  NULL;

  if (pkth.caplen < ETH_HEAD_LEN + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
#if 0
    ACE_DEBUG((LM_ERROR, "pkth.caplen < ETH_HEAD_LEN + sizeof(struct iphdr) + sizeof(struct tcphdr)\n"));
#endif
    return -1;
  }

  ethhdr = (struct ether_header *)pkt;

  if (ntohs(ethhdr->ether_type) == ETH_P_IP) {	//0x0800
    iph = (struct iphdr *)(pkt + ETH_HEAD_LEN);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy ETH_P_IP sip=%s, dip=%s\n", CIDR::ntos(iph->saddr),
               CIDR::ntos(iph->daddr)));
#endif
  } else if (ntohs(ethhdr->ether_type) == ETH_P_8021Q) {	//0x8100
    if (ntohs(*(uint16_t *)(pkt + ETH_HEAD_LEN + 2)) != ETH_P_IP) {	//0x0800
      return -1;
    }

    iph = (struct iphdr *)(pkt + ETH_HEAD_LEN + VLAN_HEAD_LEN);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s, dip=%s ETH_P_8021Q \n", CIDR::ntos(iph->saddr),
               CIDR::ntos(iph->daddr)));
#endif
  } else {
    return -1;
  }

  if (iph->protocol == IPPROTO_TCP) {
    if (pkth.caplen < (ETH_HEAD_LEN + iph->ihl * 4 + sizeof(struct tcphdr))) {
      return -1;
    }

    tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s:%d, dip=%s:%d IPPROTO_TCP\n", CIDR::ntos(iph->saddr),
               ntohs(tcph->source), CIDR::ntos(iph->daddr), ntohs(tcph->dest)));
#endif

    // ignore tcp without payload. but remember frame is has syn, fin, rst flag.
    if ((ntohs(iph->tot_len) == iph->ihl * 4 + tcph->doff * 4)
        && (!tcph->syn && !tcph->fin && !tcph->rst)) {
      return -1;
    }
  } else if (iph->protocol == IPPROTO_UDP) {
    // UDP must has payload.
    if (pkth.caplen < (ETH_HEAD_LEN + iph->ihl * 4 + sizeof(struct udphdr))) {
      return -1;
    }

    //TODO::添加UDP的协议头
  }

  memcpy(&this->ts, &pkth.ts, sizeof(struct timeval));
  this->caplen = std::min(ETH_HEAD_LEN + ntohs(iph->tot_len), (int)sizeof(this->pkt));
  this->caplen = std::min(caplen, pkth.caplen);
  memcpy(this->pkt, pkt, ETH_HEAD_LEN - 2);
  *(uint16_t *)(this->pkt + 12) = htons(0x0800);
  memcpy(this->pkt + ETH_HEAD_LEN, (char *)iph, this->caplen - ETH_HEAD_LEN);
  return 0;
}

/*!
 * parse the tcp payload after the tcp header into a pointer.
 * @return payload length on success or < 0 on error.
 */
int Frame::copy(const FrameHdr &framehdr)
{
  const struct iphdr *iph = NULL;
  const struct ether_header *ethhdr =  NULL;
  ethhdr = (struct ether_header *)framehdr.pkt;

  if (ntohs(ethhdr->ether_type) == ETH_P_IP) {	//0x0800
    iph = (struct iphdr *)(framehdr.pkt + ETH_HEAD_LEN);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s, dip=%s ETH_P_IP\n", CIDR::ntos(iph->saddr),
               CIDR::ntos(iph->daddr)));
#endif
  } else if (ntohs(ethhdr->ether_type) == ETH_P_8021Q) {	//0x8100
    if (ntohs(*(uint16_t *)(framehdr.pkt + ETH_HEAD_LEN + 2)) != ETH_P_IP) {	//0x0800
      return -1;
    }

    iph = (struct iphdr *)(framehdr.pkt + ETH_HEAD_LEN + VLAN_HEAD_LEN);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s, dip=%s ETH_P_8021Q \n", CIDR::ntos(iph->saddr),
               CIDR::ntos(iph->daddr)));
#endif
  } else {
    return -1;
  }

  if (iph->protocol != IPPROTO_TCP) {
    return -1;
  }

  this->caplen = std::min((uint32_t)sizeof(this->pkt), framehdr.caplen);
  memcpy(this->pkt, framehdr.pkt, ETH_HEAD_LEN - 2);
  *(uint16_t *)(this->pkt + 12) = htons(0x0800);
  memcpy(this->pkt + ETH_HEAD_LEN, (char *)iph, this->caplen - ETH_HEAD_LEN);
  return 0;
}

/*!
 * Frame_Hdr = funnction.
 */
FrameHdr &FrameHdr::operator= (const FrameHdr &f)
{
  if (this == &f) {
    return *this;
  }

  assert(f.caplen <= sizeof(pkt));
  caplen = f.caplen;
  ts = f.ts;
  memcpy(pkt, f.pkt, sizeof(struct timeval) + sizeof(uint32_t) + f.caplen);
  return *this;
}

/*!
 * parse the tcp payload after the tcp header into a pointer.
 * @return payload length on success or < 0 on error.
 */
int FrameHdr::copy(const struct pcap_pkthdr &pkth, const uint8_t *pkt)
{
  const struct iphdr *iph = NULL;
  const struct tcphdr *tcph = NULL;
  const struct ether_header *ethhdr =  NULL;

  if (pkth.caplen < Frame::ETH_HEAD_LEN + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
    return -1;
  }

  ethhdr = (struct ether_header *)pkt;

  if (ntohs(ethhdr->ether_type) == 0x0800) {	// ETH_P_IP
    iph = (struct iphdr *)(pkt + Frame::ETH_HEAD_LEN);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s, dip=%s ETH_P_IP\n", CIDR::ntos(iph->saddr),
               CIDR::ntos(iph->daddr)));
#endif
  } else if (ntohs(ethhdr->ether_type) == 0x8100) {	// ETH_P_8021Q
    if (ntohs(*(uint16_t *)(pkt + Frame::ETH_HEAD_LEN + 2)) != 0x0800) {	// ETH_P_IP
      return -1;
    }

    iph = (struct iphdr *)(pkt + Frame::ETH_HEAD_LEN + Frame::VLAN_HEAD_LEN);
#if 0
    ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s, dip=%s ETH_P_8021Q\n", CIDR::ntos(iph->saddr),
               CIDR::ntos(iph->daddr)));
#endif
  } else {
    return -1;
  }

  if (iph->protocol != IPPROTO_TCP) {
    return -1;
  }

  if (pkth.caplen < (Frame::ETH_HEAD_LEN + iph->ihl * 4 + sizeof(struct tcphdr))) {
    return -1;
  }

  tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
#if 0
  ACE_DEBUG((LM_DEBUG, " Frame copy sip=%s:%d, dip=%s:%d\n", CIDR::ntos(iph->saddr),
             CIDR::ntos(iph->daddr), ntohs(tcph->source), ntohs(tcph->dest)));
#endif

  // ignore tcp with payload.
  if (ntohs(iph->tot_len) != iph->ihl * 4 + tcph->doff * 4) {
    return -1;
  }

  memcpy(&this->ts, &pkth.ts, sizeof(struct timeval));
  this->caplen = std::min((int)((char *)iph - (char *)ethhdr) + ntohs(iph->tot_len), (int)sizeof(this->pkt));
  memcpy(this->pkt, pkt, this->caplen);
  return 0;
}

char *FrameHdr::dump(char *buf, int len) const
{
  const struct iphdr *iph = NULL;
  const struct tcphdr *tcph = NULL;

  if (ntohs(*(uint16_t *)(pkt + 12)) == 0x8100) {	// ETH_P_8021Q
    iph = (struct iphdr *)(pkt + Frame::ETH_HEAD_LEN + Frame::VLAN_HEAD_LEN);
  } else {
    iph = (struct iphdr *)(pkt + Frame::ETH_HEAD_LEN);
  }

  if (iph->protocol != IPPROTO_TCP) {
    return buf = NULL;
  }

  tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
  char tmp[48] = {0};
  snprintf(buf, len - 1, "%s\t%s:%d -> %s:%d | %d:%d, %d:%d", ctime(&this->ts.tv_sec),
           CIDR::ntos(iph->saddr), ntohs(tcph->source),
           CIDR::ntos(iph->daddr, tmp, sizeof(tmp)), ntohs(tcph->dest),
           this->caplen, (int)(Frame::ETH_HEAD_LEN + iph->ihl * 4 + sizeof(struct tcphdr)), ntohs(iph->tot_len), iph->ihl * 4 + tcph->doff * 4);
  return buf;
}

std::ostream &operator << (std::ostream &os, const FrameHdr &frm)
{
  const struct iphdr *iph = frm.iphdr();
  const struct tcphdr *tcph = frm.tcphdr();

  if (tcph == NULL) {
    return os << "error frame.";
  }

  os << CIDR::ntos(iph->saddr) << ":" << ntohs(tcph->source) << " -> ";
  os << CIDR::ntos(iph->daddr) << ":" << ntohs(tcph->dest) << " : ";

  if (tcph->syn) {
    os << "S";
  } else if (tcph->fin) {
    os << "F";
  } else if (tcph->rst) {
    os << "R";
  } else if (tcph->psh) {
    os << "P";
  } else if (tcph->ack) {
    os << "A";
  }

  os << " : " << frm.ts.tv_sec;
  return os;
}

