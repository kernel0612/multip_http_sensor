#include "GatherOutputer.h"
#include "GatherClassifier.h"
#include "ServiceDef.h"
#include "CIDR.h"
#include <string>
#include <strstream>

const std::string GatherOutputer::ENGINE_INPUT = static_cast<std::string>(PREFIX_HOME) + "/tmp/.s.engine.input";
const std::string GatherOutputer::GATHER_OUTPUT = static_cast<std::string>(PREFIX_HOME) + "/tmp/.s.gather.output";
GatherOutputer::GatherOutputer(GatherClassifier &classifier)
  : classifier_(classifier), succ_(0), fail_(0)
{
  peer_.set(ENGINE_INPUT.c_str());
}

/*!
 * Create Audit_Outputer object and output buffer.
 * @return 0 on success and < 0 on error.
 */
int GatherOutputer::create()
{
//  unlink(GATHER_OUTPUT.c_str());
//  ACE_UNIX_Addr my_addr(GATHER_OUTPUT.c_str());
//
//  if (this->unix_dgram_.open(my_addr) == -1) {
//    ACE_DEBUG((LM_ERROR, " Ctrl_Outputer: open UNIX SOCKET failed: %s\n", my_addr.get_path_name()));
//    return -1;
//  }

  return 0;
}

/*!
 * Destroy Audit_Outputer object and output buffer.
 * @return 0 on success and < 0 on error.
 */
int GatherOutputer::destroy()
{
  unix_dgram_.close();
  return 0;
}

//! Dump object.
void GatherOutputer::dump(std::ostream &os) const
{
  os << "[GatherOutputer]\tstatistic success/failed: " << succ_ << '/' << fail_ << std::endl;
  os << "\tto unix address: " << peer_.get_path_name() << std::endl;
}

/*!
 * Thread main function. Witch invoked by run. Do not invoke it directly.
 * @return 0 on success and < 0 on error.
 */
//int GatherOutputer::svc(void)
//{
//  int ret = 0;
//  ORMEntity *entity = NULL;
//
//  while (1) {
//    ret = classifier_.output_queue().read(&entity);
//
//    if (entity == NULL) {
//      continue;
//    }
//
//    // Output to tagent.
//#ifdef DENUG
//    //    verbose(*entity);
//#endif
//#if 1
//
//    if (unix_dgram_.send(entity, 4 + entity->len, peer_) < 0) {
//      fail_ ++;
//      ACE_DEBUG((LM_ERROR, " GatherOutputer: send unix socket failed.\n"));
//      verbose(*entity);
//    } else {
//      succ_ ++;
//    }
//
//#endif
//    classifier_.output_queue().free(entity);
//    entity = NULL;
//  }
//
//  return 0;
//}

void GatherOutputer::child(pid_t parent)
{
	 int ret = 0;
	  //ORMEntity *entity = NULL;
	 ORMEntity entity;
	 my_berkeleyDBbased_fifo<ORMEntity>* fifo=classifier_.output_fifo();
	  while (1) {
	   // ret = classifier_.output_queue().read(&entity);
          ret=fifo->pop_front(entity);
	    if (/*entity == NULL */ret!=0) {
	      continue;
	    }
        sleep(1);
	    // Output to tagent.
	#ifdef DENUG
	    //    verbose(*entity);
	#endif
	#if 1

//	    if (unix_dgram_.send(&entity, 4 + entity.len, peer_) < 0) {
//	      fail_ ++;
//	      ACE_DEBUG((LM_ERROR, " GatherOutputer: send unix socket failed.\n"));
//	      verbose(entity);
//	    } else {
//	      succ_ ++;
//	    }

	#endif
	    //classifier_.output_queue().free(entity);
	    //entity = NULL;
	  }
}
int  GatherOutputer::prepare(ACE_Process_Options& options)
{
	ACE_DEBUG((LM_INFO, " GatherOutputer prepare build.\n"));
	return 0;
}
void GatherOutputer::verbose(ORMEntity &entity)
{
  if (entity.type == ORMEntity::STREAM) {
    ORMStream s = entity.un.stream;
    char buffer[2048] = {'\0'};
    snprintf(buffer, 2047, "sid=%lld, mac=%s, sip=%s, dip=%s, service=%s, itype=%d "
             "eventtype=%d data=[%s]\n",
             s.sid, s.mac, CIDR::ntos(s.sip), CIDR::ntos(s.dip),
             ServiceDef::service2name(s.service), s.itype,
             s.eventtype, s.data);
    ACE_DEBUG((LM_DEBUG, " GatherOutputer: Strem :%s", buffer));
  }

  if (entity.type == ORMEntity::TRANSACTION) {
    ORMTransaction t = entity.un.trans;
    char buffer[3096] = {'\0'};
    snprintf(buffer, 3096, "sid=%lld, sip=%s, dip=%s,  data=[%s]\n",
             t.sid, CIDR::ntos(t.sip),  CIDR::ntos(t.dip),  t.data);
    ACE_DEBUG((LM_DEBUG, " GatherOutputer: Transaction :%s", buffer));
  }
}

