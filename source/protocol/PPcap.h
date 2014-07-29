#ifndef __PCAP_H
#define __PCAP_H
#include <pcap.h>
#include <stdint.h>

/*!
 * @brief The class defines libpcap's wrap.
 */
class PPcap
{
public:
  PPcap();
  ~PPcap() {};

public:
  //! Open libpcap object.
  int open(const char *interface, const char *filter);

  int open(const char *filename);

  //! Get next frame.
  int get_next(struct pcap_pkthdr *pkth, const uint8_t **pkt);

  //! Get error.
  const char *error() const {
    return err_;
  }

  //! Close libpcap object.
  int close();

  //! Get libpcap state.
  int stats(uint32_t &recved, uint32_t &droped);

private:
  PPcap(const PPcap &cap);
  PPcap &operator=(const PPcap &cap);

protected:
  //! libpcap handle.
  pcap_t *handle_;

  //! libpcap error buffer.
  char err_[PCAP_ERRBUF_SIZE];
};


#endif

