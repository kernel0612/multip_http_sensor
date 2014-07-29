#include "StreamDispatcher.h"
//#include "GatherEventManager.h"
#include "ServiceDef.h"
#include "CIDR.h"

#include <ace/Log_Msg.h>

StreamDispatcher::StreamDispatcher(GatherClassifier &classifier)
  : classifier_(classifier)
{
}

//! Creata Stream_Dispatcher object.
int StreamDispatcher::create()
{
  int ret = 0;

//  if ((ret = policy_.create()) < 0) {
//    ACE_DEBUG((LM_ERROR, " StreamDispatcher: load policy failed: %d, %s.\n", ret, policy_.rule_file()));
//    return -1;
//  }

  mutex_.acquire();
  // base on policy build host map, subnet map and peer map.
  clientList = policy_.clientRules();
  serviceList = policy_.serviceRules();
  mutex_.release();
  return 0;
}

//! Destroy  Stream_Dispatcher object.
int StreamDispatcher::destroy()
{
  policy_.destroy();
  mutex_.acquire();
  clientList.clear();
  serviceList.clear();
  mutex_.release();
  return 0;
}

//! Dump  Stream_Dispatcher object.
void StreamDispatcher::dump(std::ostream &os) const
{
  os << "StreamDispatcher, policy:\n";
  policy_.dump(os);
  mutex_.acquire();
  os << "\n\t[client] " << clientList.size() << "\n";
  std::vector<ClientRules>::const_iterator hit = clientList.begin();

  for (; hit != clientList.end(); ++hit) {
    os << "\t\t" << CIDR::ntos(hit->sip) << '/' <<
       CIDR::ntos(hit->smask) << "\t audit " << hit->audit << std::endl;
  }

  os << "\t[services] " << serviceList.size() << "\n";
  std::vector<SevicesRules>::const_iterator sit = serviceList.begin();

  for (; sit != serviceList.end(); ++sit) {
    os << "\t\t" << CIDR::ntos(sit->dip) << '/';
    os << CIDR::ntos(sit->dmask) << ":" << sit->dport << ":" << sit->dport << std::endl;
    std::vector<ClientRules>::const_iterator client = sit->rejectList.begin();

    for (; client != sit->rejectList.end(); ++client) {
      os << "\t\t" << CIDR::ntos(client->sip) << '/' <<
         CIDR::ntos(client->smask) << "\t audit " << client->audit << std::endl;
    }
  }

  mutex_.release();
}

//! Thread main function for ACE invoke it.
//int StreamDispatcher::svc(void)
//{
//  int ret = 0;
//  Frame *frame = NULL;
//  StreamKey key = {0};
//
//  while (1) {
//    classifier_.tcp_queue().read(&frame);
//
//    if (frame == NULL) {
//      continue;
//    }
//
//    // Check whether frame should be audit. If not drop it.
//    // First check subnets, then check hosts.
//    key.copy(*frame);
//
//    if (find_host(key) == ClientRules::DROP) {
//      classifier_.tcp_queue().free(frame);
//      frame = NULL;
//      continue;
//    }
//
//    ret = classifier_.dispatch(frame);
//
//    if (ret < 0) {
//      classifier_.tcp_queue().free(frame);
//      frame = NULL;
//      ACE_DEBUG((LM_ERROR, " StreamDispatcher: %s:%d->%s:%d[GATHER]->TCP QUEUE is failed.\n", CIDR::ntos(key.saddr),
//                 ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
//    }
//  }
//
//  return 0;
//}
void StreamDispatcher::child(pid_t parent)
{
	  int ret = 0;
	 // Frame *frame = NULL;
	  StreamKey key = {0};
	  my_berkeleyDBbased_fifo<Frame>* fifo=classifier_.capted_fifo();
      Frame frame;
      ACE_DEBUG((LM_INFO, " StreamDispatcher: child process begin.\n"));
	  while (1) {
	    /* classifier_.tcp_queue().read(&frame);*/
		   ret=fifo->pop_front(frame);
	    if (/*frame == NULL*/ret!=0) {
	      continue;
	    }

	    // Check whether frame should be audit. If not drop it.
	    // First check subnets, then check hosts.
	   // key.copy(*frame);
        key.copy(frame);
//	    if (find_host(key) == ClientRules::DROP) {
//	      //classifier_.tcp_queue().free(frame);
//	      //frame = NULL;
//	      continue;
//	    }
        sleep(1);
	    ret = classifier_.dispatch(&frame);

	    if (ret < 0) {
	     // classifier_.tcp_queue().free(frame);
	      //frame = NULL;
	      ACE_DEBUG((LM_ERROR, " StreamDispatcher: %s:%d->%s:%d[GATHER]->TCP QUEUE is failed.\n", CIDR::ntos(key.saddr),
	                 ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
	    }
	  }
}
int  StreamDispatcher::prepare(ACE_Process_Options& options)
{
	ACE_DEBUG((LM_INFO, " StreamDispatcher prepare build.\n"));
	return 0;
}


int StreamDispatcher::reload()
{
  destroy();
  return create();
}

int StreamDispatcher::find_host(StreamKey &key)
{
  mutex_.acquire();
  std::vector<SevicesRules>::const_iterator hit = serviceList.begin();

  for (; hit != serviceList.end(); ++hit) {
#if 0
    ACE_DEBUG((LM_DEBUG, "Service StreamKey [%s:%d->%s:%d] rule[%s/%s:%d]\n",
               CIDR::ntos(key.saddr), ntohs(key.sport), CIDR::ntos(key.daddr),
               ntohs(key.dport), CIDR::ntos(hit->dip), CIDR::ntos(hit->dmask),
               ntohs(hit->dport)));
#endif

    if ((hit->dip == (key.daddr & hit->dmask) &&
         (hit->dport == 0 || hit->dport == key.dport)) ||
        (hit->dip == (key.saddr & hit->dmask) &&
         (hit->dport == 0 || hit->dport == key.sport))) {
#if 0
      ACE_DEBUG((LM_DEBUG, "Service StreamKey [%s:%d->%s:%d] rule[%s/%s:%d] is Service.\n",
                 CIDR::ntos(key.saddr), ntohs(key.sport), CIDR::ntos(key.daddr),
                 ntohs(key.dport), CIDR::ntos(hit->dip), CIDR::ntos(hit->dmask),
                 ntohs(hit->dport)));
#endif
      std::vector<ClientRules>::const_iterator iit = hit->rejectList.begin();

      for (; iit != hit->rejectList.end(); ++iit) {
        if (iit->sip == (key.saddr & iit->smask) ||
            iit->sip == (key.daddr & iit->smask)) {
#if 0
          ACE_DEBUG((LM_DEBUG, "Service StreamKey [%s:%d->%s:%d] rule[%s/%s:%d] is Service, client[%s/%s]  is client drop.\n",
                     CIDR::ntos(key.saddr), ntohs(key.sport), CIDR::ntos(key.daddr),
                     ntohs(key.dport), CIDR::ntos(hit->dip), CIDR::ntos(hit->dmask),
                     ntohs(hit->dport), CIDR::ntos(iit->sip), CIDR::ntos(iit->smask)));
#endif
          mutex_.release();
          return iit->audit;
        }
      }
    }
  }

  std::vector<ClientRules>::const_iterator iiit = clientList.begin();

  for (; iiit != hit->rejectList.end(); ++iiit) {
#if 0
    ACE_DEBUG((LM_DEBUG, "Service StreamKey [%s->%s] no service.\n",
               CIDR::ntos(key.saddr), CIDR::ntos(key.daddr)));
#endif

    if (iiit->sip == (key.saddr & iiit->smask) ||
        iiit->sip == (key.daddr & iiit->smask)) {
#if 0
      ACE_DEBUG((LM_DEBUG, "Service StreamKey [%s->%s] no service,"
                 "rule[%s/%s] is client\n",
                 CIDR::ntos(key.saddr), CIDR::ntos(key.daddr),
                 CIDR::ntos(iiit->sip), CIDR::ntos(iiit->smask)));
#endif
      mutex_.release();
      return iiit->audit;
    }
  }

  mutex_.release();
  return ClientRules::DROP;
}

//! return -1 means error. 0 means OK.
int StreamDispatcher::find_gather_policy(const StreamKey &key, int &service)
{
  service = 0;
  int ret = policy_.find_policy(key, service);
#if 0
  ACE_DEBUG((LM_DEBUG, " StreamDispatcher: key sport:dport : %d:%d service: "
             "%d ret=%d.\n", ntohs(key.sport), ntohs(key.dport), service, ret));
#endif

  if (ret < 0)  {
    service = ServiceDef::SERVICE_OTHER;
    return ret;
  }

  // Now audit > 0. If service == sport, maybe direct is wrong.
  // And service should be in our could audit scare. Means should be inside our audit port.
  if (service == 0 || service == ntohs(key.sport)) {
    service = ntohs(key.dport);

    if (ServiceDef::find(service) == 0) {
      service = ServiceDef::SERVICE_OTHER;
    }
  }

  return 0;
}

