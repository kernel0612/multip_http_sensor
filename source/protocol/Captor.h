#ifndef __CAPTOR_H
#define __CAPTOR_H

#include <ace/Task.h>
#include <ace/Process.h>    //added by xlf 2014/7/21
#include <pcap.h>
#include <stdint.h>
#include <ctime>

#include "PPcap.h"
#include "Frame.h"

/*!
 * @brief The class defines Captor thread to capture ethernet frame.
 */
template <class T>
class Captor : public ACE_Process
{
public:
  //! Constructor with packet classifier.
  Captor(T &classfier, int id = 0);
  virtual ~Captor() {
    destroy();
  }

  //! Creata Captor object.
  int create();

  //! Destroy Captor object.
  int destroy();

  //! Thread main function for ACE invoke it.
  //virtual int svc(void);

  //added by xlf   2014/7/21
  virtual void child(pid_t parent);
  virtual int prepare(ACE_Process_Options& options);
  //! Set network interface.
  void interface(const char *ni) {
    strncpy(interface_, ni, sizeof(interface_));
  }

  //! Get network interface.
  const char *interface() const {
    return interface_;
  }

  //! Set libpcap filter.
  void filter(const char *f) {
    strncpy(filter_, f, sizeof(filter_));
  }

  //! Get libpcap filter.
  const char *filter() const {
    return filter_;
  }

  //! Dump object.
  void dump(std::ostream &os) const;

public:
  //! Classifier for packet classifed.
  T &classifier_;

  //! Network interface.
  char interface_[32];

  //! BPF (Berkely Packet Filter) filter.
  char filter_[256];

  //! Pcap object.
  PPcap pcap_;

  //! Captor ID.
  int id_;

  //! Statistic;
  uint32_t statis_;
  uint32_t bytes_;
  time_t start_;
  uint32_t speed_;
};


template <class T>
Captor<T>::Captor(T &classifier, int id) : classifier_(classifier), id_(id), statis_(0), bytes_(0), start_(0), speed_(0)
{
  memset(interface_, 0, sizeof(interface_));
  memset(filter_, 0, sizeof(filter_));
}

/*!
 * Open pcap.
 * @return 0 on success or < 0 on error.
 */
template <class T>
int Captor<T>::create()
{
  if (pcap_.open(interface_, filter_) < 0) {
    ACE_DEBUG((LM_ERROR, " Captor: open network interface \'%s\' with filter \'%s\' failed: %s.\n", interface_, filter_, pcap_.error()));
    return -1;
  } else {
    ACE_DEBUG((LM_DEBUG, " Captor: open network interface \'%s\' with filter \'%s\' succeed: %s.\n", interface_, filter_, pcap_.error()));
  }

  return 0;
}

/*!
 * Close pcap.
 * @return 0 on success or < 0 on error.
 */
template <class T>
int Captor<T>::destroy()
{
  pcap_.close();
  return 0;
}

/*!
 * Thread entry.
 * @return 0 on success or < 0 on error.
 */
//template <class T>
//int Captor<T>::svc(void)
//{
//  struct pcap_pkthdr pkth;
//  const uint8_t *pkt;
//  ACE_DEBUG((LM_INFO, " Captor: thread begin with interface \'%s\'.\n", interface_));
//  start_ = time(NULL);
//
//  while (1) {
//    if (pcap_.get_next(&pkth, &pkt) < 0) {
//      break;
//    }
//
//    classifier_.classify(pkth, pkt);
//    statis_ ++;
//    bytes_ += pkth.len;
//  }
//
//  return 0;
//}
template <class T>
void Captor<T>::child(pid_t parent)
{
	  struct pcap_pkthdr pkth;
	  const uint8_t *pkt;
	  ACE_DEBUG((LM_INFO, " Captor: thread begin with interface \'%s\'.\n", interface_));
	  start_ = time(NULL);

	  while (1) {
	    if (pcap_.get_next(&pkth, &pkt) < 0) {
	      break;
	    }
        sleep(1);
	    classifier_.classify(pkth, pkt);
	    statis_ ++;
	    bytes_ += pkth.len;
	  }
}
template <class T>
int  Captor<T>::prepare(ACE_Process_Options& options)
{
	ACE_DEBUG((LM_INFO, " Captor prepare build.\n"));
	return 0;
}


//! Dump object.
template <class T>
void Captor<T>::dump(std::ostream &os) const
{
  os << "interface: " << interface_;
  os << ",\tstatistic: " << statis_ << ",\tspeed: " << bytes_ * 8 / (time(NULL) - start_) / (1024 * 1024) << " Mbps" << std::endl;
}


#endif

