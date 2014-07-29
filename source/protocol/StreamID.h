#ifndef __STREAMID_H
#define __STREAMID_H

#include "Random.h"
#include <ace/Synch.h>
#include <ace/Singleton.h>
#include <string>

/*!
 * @brief The class defines Output Buffer singleton.
 */
class StreamID
{
  friend class ACE_Singleton<StreamID, ACE_Thread_Mutex>;
private:
  StreamID() {
    init();
  }
  ~StreamID() { }

public:
  //! create StreamID object.
  int init();

  //! getsid
  int64_t sid();

  Random &random() {
    return random_;
  }

  static const std::string STREAMID_FILE;

protected:
  //! Buffer capacity, it is const integer.
  Random random_;

  //! mutex
  ACE_Thread_Mutex mutex_;
};

//! Define StreamID singleton.
typedef ACE_Singleton<StreamID, ACE_Thread_Mutex> StreamID_Single;


#endif //__STREAMID_H

