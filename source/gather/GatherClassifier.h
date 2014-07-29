#ifndef __CLASSIFIER_H
#define __CLASSIFIER_H

#include "CachedFIFO.h"
#include "ThreadFIFO.h"
#include "Frame.h"
#include "Orm.h"
#include <stdint.h>
#include <map>
#include"my_berkeleyDBbased_fifo.h"   //added by xlf    2014/7/21

/*!
 * @brief The class defines packet clissifier.
 */
class GatherClassifier
{
public:
  //  typedef struct StatisHost {
  //    uint32_t ip;
  //    uint64_t bytes;
  //    uint64_t bytes_request;
  //    uint64_t bytes_response;
  //    uint64_t frames;
  //    uint64_t frames_request;
  //    uint64_t frames_response;
  //  };
  //
  //  typedef struct StatisService {
  //    int service;
  //    uint64_t bytes;
  //    uint64_t bytes_request;
  //    uint64_t bytes_response;
  //    uint64_t frames;
  //    uint64_t frames_request;
  //    uint64_t frames_response;
  //  } StatisService;
  //
  //  typedef struct StatisCaptor {
  //    int captor_id;
  //    std::map<uint32_t, StatisHost> mhosts;		// Key is ip address.
  //  } StatisCaptor;

  enum { DEFAULT_SIZE = 1024, MAX_CAPTOR = 16, AUDITOR_NUM = 1 };

  GatherClassifier();
  GatherClassifier(int size);
  ~GatherClassifier() {}

  //! Create Classifier object.
  int create();

  //! Destroy Classifier object.
  int destroy();

  //! Classify ethernet frame.
  int classify(Frame &frame);

  //! Classify ethernet frame.
  int classify(const struct pcap_pkthdr &pkth, const uint8_t *pkt, int captor_id = 0);

  //! dispatcher ethernet frame.
  int dispatch(Frame *frame);

  //! Dump
  void dump(std::ostream &os) const;

  //! get tcp queue.
  inline CachedFIFO<Frame> &tcp_queue() const {
    return *tcp_queue_;
  }

  //! get output queue.
  inline CachedFIFO<ORMEntity> &output_queue() const {
    return *output_queue_;
  }

  //! get auditor fifo by index.
  //  inline ThreadFIFO<Frame *> *fifo(int index) {
  //    if (index > 0 && index < 6) {
  //      return NULL;
  //    }
  //
  //    return &auditor_fifo_[index];
  //  }

  inline ThreadFIFO<Frame *> *fifo(int index = 0) {
    return &auditor_fifo_;
  }

  inline my_berkeleyDBbased_fifo<Frame>* capted_fifo() {            //added by xlf  2014/7/21
	  return &_capted_fifo;
  }
  inline my_berkeleyDBbased_fifo<ORMEntity>* output_fifo()  {       //added by xlf 2014/7/21
	  return &_output_fifo;
  }
  inline my_berkeleyDBbased_fifo<Frame>* auditor_fifo() {            // added by xlf 2014/7/22
	  return & _auditor_fifo;
  }
public:
  int device_id;

protected:
  //! buffer size
  const int buffer_size_;

  //! TCP frame buffer.
  CachedFIFO<Frame> *tcp_queue_;

  //! UDP frame buffer.
  CachedFIFO<ORMEntity> *output_queue_;

  //! Stream auditor fifos.
  //  ThreadFIFO<Frame *> auditor_fifo_[6];
  ThreadFIFO<Frame *> auditor_fifo_;
  my_berkeleyDBbased_fifo<Frame> _capted_fifo;                   //added by xlf 2014/7/21
  my_berkeleyDBbased_fifo<ORMEntity> _output_fifo;               //added by xlf 2014/7/21
  my_berkeleyDBbased_fifo<Frame> _auditor_fifo;                  //added by xlf 2014/7/22
  //! Statistics.
  //  std::map<uint32_t, StatisHost> mhosts_;		// Key is ip address.
  //  std::map<int, StatisService> mservices_;		// Key is service.
  //  StatisCaptor vcaptors_[16];			// Index is captor_id.
};

#endif //__CLASSIFIER_H

