#ifndef __GATHER_OUTPUTOR_H
#define __GATHER_OUTPUTOR_H

#include <ace/Task.h>
#include <ace/LSOCK_Dgram.h>
#include <ace/UNIX_Addr.h>

#include "version.h"
#include "Orm.h"
#include "GatherClassifier.h"
#include "ace/Process.h"   //added by xlf 2014/7/21

/*!
 * @brief The class defines audit outputer thread.
 */
class GatherOutputer : public ACE_Process
{
public:
  GatherOutputer(GatherClassifier &classifier);
  virtual ~GatherOutputer() {
    destroy();
  }

  //! Create audit outputor object.
  int create();

  //! Destroy audit outputor object.
  int destroy();

  //! Dump object.
  void dump(std::ostream &os) const;

  //! Thread main.
 // virtual int svc(void);

  //! Process main.                           //added by xlf 2014/7/21
  virtual int  prepare(ACE_Process_Options& options);
  virtual void child(pid_t parent);

  static const std::string ENGINE_INPUT;
  static const std::string GATHER_OUTPUT;
private:
  void verbose(ORMEntity &entity);

protected:
  //! Output buffer point.
  GatherClassifier &classifier_;

  //! Unix socket to tagent.
  ACE_LSOCK_Dgram unix_dgram_;
  ACE_UNIX_Addr peer_;

  //! statistics.
  int succ_;
  int fail_;
};


#endif
