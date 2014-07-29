#include "PPcap.h"
#include <pcap.h>
#include <cassert>
#include <cstring>



PPcap::PPcap() : handle_(NULL)
{
  memset(err_, 0, sizeof(err_));
}

/*!
 * Open libpcap handle and set the interface and filter.
 * @param interface can be file name dumped by libpcap or ethernet interface.
 * @param filter string of the pcap filter such as "tcp and udp".
 * @return 0 on success and -1 on error. And use get_err to get error information.
 */
int PPcap::open(const char *interface, const char *filter)
{
  if (handle_ != NULL) {
    close();
  }

  assert(interface != NULL);
  assert(filter != NULL);
  bpf_u_int32 mask = 0;			/* Our netmask */
  bpf_u_int32 net = 0;			/* Our IP */

  /* Find the properties for the device
   * If look up net failed, means you maybe not set the ip address and netmask for the interface.
   * Ignore this fail.
   */
  if (pcap_lookupnet((char *)interface, &net, &mask, err_) == -1) {
    strncpy(err_, "Lookup pcap device failed, because interface is down or you are not root.", sizeof(err_));
    // ignore the failed.
  }

  int snaplen = 1518;			// 1500 + ETH_HEAD_LEN + VLAN_EEAD_LEN;
  int timeout = 0;                        /* 0:is not set overtime*/

  /* Open the interface as the network device in promiscuous mode.
   * And if open live failed, assume interface as a offline packet source.
   */
  if ((this->handle_ = pcap_open_live((char *)interface, snaplen, 1, timeout, err_)) == NULL) {
    if ((this->handle_ = pcap_open_offline(interface, err_)) == NULL) {
      strncat(err_, ". Or you are not root to open the interface.", sizeof(err_));
      return -1;
    }
  }

  struct bpf_program bpf_filter = {0};	/* The compiled filter */

  /* Compile and apply the filter */
  if (pcap_compile(this->handle_, &bpf_filter, (char *)filter, 0, net) == -1) {
    strncpy(err_, pcap_geterr(handle_), sizeof(err_));
    return -1;
  }

  if (pcap_setfilter(this->handle_, &bpf_filter) == -1) {
    strncpy(err_, pcap_geterr(handle_), sizeof(err_));
    return -1;
  }

  return 0;
}

int PPcap::open(const char *filename)
{
  if ((this->handle_ = pcap_open_offline(filename, err_)) == NULL) {
    strncat(err_, ". Or you are not root to open the interface.", sizeof(err_));
    return -1;
  }

  return 0;
}

/*!
 * Get next libpcap packet frame.
 * @param pkth for getting packet header information.
 * @param pkt for getting the packet octes.
 * @return 0 on success and -1 on error. And use get_err to get error information.
 */
int PPcap::get_next(struct pcap_pkthdr *pkth, const uint8_t **pkt)
{
  if ((*pkt = pcap_next(this->handle_, pkth)) == NULL) {
    strncpy(err_, pcap_geterr(handle_), sizeof(err_));
    return -1;
  }

  return 0;
}

/*!
 * Close the opend libpcap handle.
 * @return always return 0 whitch means success.
 */
int PPcap::close()
{
  if (this->handle_ != NULL) {
    pcap_close(this->handle_);
  }

  this->handle_ = NULL;
  return 0;
}

/*!
 * Get pcap received and droped number of frames.
 * @param recved return received number of frames.
 * @param droped return droped number of frames.
 * @return 0 on success and -1 on error. And use get_err to get error information.
 */
int PPcap::stats(uint32_t &recved, uint32_t &droped)
{
  struct pcap_stat stat = {0};

  if (pcap_stats(this->handle_, &stat) < 0) {
    strncpy(err_, pcap_geterr(handle_), sizeof(err_));
    return -1;
  }

  recved = stat.ps_recv;
  droped = stat.ps_drop;
  return 0;
}

