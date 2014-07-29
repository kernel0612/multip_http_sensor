#include "StreamID.h"
#include "version.h"


const std::string StreamID::STREAMID_FILE = static_cast<std::string>(PREFIX_HOME) + "/tmp/.gather.sid";

int StreamID::init()
{
  int ret = random_.init(1, 16, STREAMID_FILE.c_str());

  if (ret < 0) {
    return -1;
  }

  return 0;
}

//! getsid
int64_t StreamID::sid()
{
  volatile int64_t s = 0;
  mutex_.acquire();
  s = random_.rand();
  mutex_.release();
  return s;
}

