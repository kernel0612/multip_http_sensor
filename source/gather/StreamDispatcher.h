#ifndef __STREAM_DISPATCHER_H
#define __STREAM_DISPATCHER_H

#include "GatherPolicy.h"
#include "Stream.h"
#include "PMap.h"
#include "GatherClassifier.h"

#include <ace/Task.h>
#include <ace/Process.h>

/*!
 * @brief This class defines stream dispatcher.
 */
class StreamDispatcher : public ACE_Process
{
public:
  StreamDispatcher(GatherClassifier &classifier);
  virtual ~StreamDispatcher() {
    destroy();
  }

  //! Creata Stream_Dispatcher object.
  int create();

  //! Destroy  Stream_Dispatcher object.
  int destroy();

  //! Dump  Stream_Dispatcher object.
  void dump(std::ostream &os) const;

  //! Thread main function for ACE invoke it.
  //virtual int svc(void);

  //! Process main.                           //added by xlf 2014/7/21
  virtual int  prepare(ACE_Process_Options& options);
  virtual void child(pid_t parent);


  int reload();

  GatherPolicy &policy() {
    return policy_;
  }

  int find_gather_policy(const StreamKey &key, int &service);

protected:
  int find_host(StreamKey &key);

protected:
  //! IP frame buffer.
  GatherClassifier &classifier_;

  //! audit rule.
  GatherPolicy policy_;

  //! audit rule mutex; Maybe not need it. Because policy will not modify any more.
  //! It is a reload mutex.
  mutable ACE_Thread_Mutex mutex_;

  //! Host map should be audit. And subnet map should be audit, Big netmaks first.
  std::vector<ClientRules> clientList;
  std::vector<SevicesRules> serviceList;
};

#endif //__STREAM_DISPATCHER_H

