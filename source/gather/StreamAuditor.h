#ifndef __STREAM_AUDITOR_H
#define __STREAM_AUDITOR_H

#include "Stream.h"
#include "CachedMap.h"
#include "ThreadFIFO.h"
#include "Dissector.h"
#include "GatherClassifier.h"
#include "StreamDispatcher.h"

#include <vector>
#include <ace/Task.h>
#include <ace/Process.h>

#include "StreamMap.h"                 //added by xlf 2014/7/28
#include "globalconfig.h"              //added by xlf 2014/7/29
typedef CachedMap<StreamKey, Stream> Stream_Table;

/*!
 * @brief This class defines stream auditor.
 */
class StreamAuditor : public ACE_Process
{
public:
  enum { MAX_STREAM = 102400, STREAM_TIMEOUT = 600 };
  StreamAuditor(GatherClassifier &classifier, StreamDispatcher &dispatcher);
  virtual ~StreamAuditor() {
    destroy();
  }

  //! Create Stream_Auditor object.
  int create();

  //! Destroy Stream_Auditor object.
  int destroy();

  //! Dump object.
  void dump(ostream &os) const;
  void dump_stream(ostream &os, int param = 0, int service = 0, uint32_t sip = 0, uint32_t dip = 0, int sport = 0, int dport = 0) const;
  void dump_stream_ini(ostream &os) const;
  void dump_stream_xml(ostream &os) const;
  void dump_mac(ostream &os) const;

  //! Thread main function for ACE invoke it.
  //virtual int svc(void);

  //! Process main.                           //added by xlf 2014/7/21
  virtual int  prepare(ACE_Process_Options& options);
  virtual void child(pid_t parent);

  //! Clean timeout stream.
  int clean_stream();

  //! Get and set max streams.
  int max_stream() const {
    return max_stream_;
  }
  void max_stream(int max) {
    max_stream_ = max;
  }
  int stream_timeout() const {
    return stream_timeout_;
  }
  void stream_timeout(int seconds) {
    if (seconds < STREAM_TIMEOUT || seconds > STREAM_TIMEOUT * 100) {
      stream_timeout_ = STREAM_TIMEOUT;
    } else {
      stream_timeout_ = seconds;
    }
  }

private:
  //! entry streams to do audit.
  int entry_streams(const Frame &frame);

  //! New a stream.
  int new_stream(const Frame &frame, const StreamKey &key);

  //! Finish a stream.
  int fin_stream(Stream &stream);

  //! Output audit stream and transaction record.
  int audit_stream(const Stream &stream, int flag) const;
  int audit_transaction(Stream &stream, int flag) const;
  int audit_more_transaction(Stream &stream);

  int check_telnet_jump(const Stream &stream, const Frame &frame, int flag);
  int fin_telnet_jump(const Stream &stream);

protected:
  //! Classifier.
  GatherClassifier &classifier_;

  //! Stream dispatcher.
  StreamDispatcher &dispatcher_;

  //! Stream table.
  int max_stream_;
  int stream_timeout_;
  Stream_Table *table_;
  StreamMap*  streammap_;           //added by xlf 2014/7/28

  //! Telnet jump stream table.
  std::map<StreamKey, std::vector<Stream> > jump_table_;

  //! Stream table mutex.
  mutable ACE_Thread_Mutex mutex_;

  //! Dissector.
  Dissector dissector_;

  //! Statistics.
  int syn_;
  int fin_;
  int repeat_;	// repeat stream statistic.
};


#endif //__STREAM_AUDITOR_H

