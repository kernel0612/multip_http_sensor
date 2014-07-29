#ifndef __DISSECTOR_HTTP_H
#define __DISSECTOR_HTTP_H

#include "Stream.h"
#include "Frame.h"
/*!
 * @brief The class defines HTTP protocol dissector.
 */
class DissectorHTTP
{
public:
  DissectorHTTP() {}
  ~DissectorHTTP() {}

  static int dissect(Stream &stream, const Frame &frame);
};

#endif //__DISSECTOR_HTTP_H

