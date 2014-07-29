#ifndef __DISSECTOR_H
#define __DISSECTOR_H

#include "Orm.h"
#include "PortChanged.h"
#include "Frame.h"
#include "Stream.h"


/*!
 * @brief The class defines protocol dissector.
 */
class Dissector
{
public:
  enum { RET_TRANSACTION = 1, RET_RESPONSE = 2, RET_ACCOUNT = 4 };

  Dissector();
  ~Dissector() {
    destroy();
  }

  int create();
  int destroy();

  //! return 1 means transaction, 2 means response, 4 means accout and others. They can be added.
  int dissect(Stream &stream, const Frame &frame);

  static PortChanged &port_changed() {
    return port_changed_;
  }

public:
  ORMTransaction trans_[10];
  int trans_num_;

protected:
  static PortChanged port_changed_;
};


#endif //__DISSECTOR_H

