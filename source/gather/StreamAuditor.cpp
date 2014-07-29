#include "StreamAuditor.h"
//#include "GatherEventManager.h"
#include "StreamDispatcher.h"
#include "Stream.h"
#include "StreamID.h"
#include "ServiceDef.h"
#include "CIDR.h"
#include "packet.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

StreamAuditor::StreamAuditor(GatherClassifier &classifier, StreamDispatcher &dispatcher)
  : classifier_(classifier), dispatcher_(dispatcher), max_stream_(MAX_STREAM), stream_timeout_(STREAM_TIMEOUT), table_(NULL)
,streammap_(0)
{
}

/*!
 * Create StreamAuditor object. Also create stream table and attach fifo.
 * @return 0 on success or < 0 on error.
 */
int StreamAuditor::create()
{
  int ret = 0;
  table_ = (Stream_Table *) operator new(sizeof(Stream_Table));
  streammap_=(StreamMap*) operator new(sizeof(StreamMap));    //added by xlf 2014/7/28
  try {
    new(table_) Stream_Table(max_stream_);
    new(streammap_) StreamMap();
  } catch (...) {
    operator delete(table_);
    table_ = NULL;
    operator delete(streammap_);   //added by xlf 2014/7/28
    streammap_=0;                   //added by xlf 2014/7/28
    ACE_DEBUG((LM_ERROR, " StreamAuditor: new stream table failed.\n"));
    throw;
    return -1;
  }

  if ((ret = table_->create()) < 0) {
    ACE_DEBUG((LM_ERROR, " StreamAuditor: create stream table failed: %d.\n", ret));
    return -1;
  }
  configure::global_config* config=configure::global_config::get_instance();
  if(!config){
	  return -1;
  }
  if((ret=streammap_->create(config->_ssdb_ip.c_str(),config->_ssdb_port))<0){             //added by xlf 2014/7/28
	    ACE_DEBUG((LM_ERROR, " StreamAuditor: create stream map failed: %d.\n", ret));
	    return -1;
  }
  return 0;
}

/*!
 * Destroy StreamAuditor object. Also destroy stream table and detach fifo.
 * @return 0 on success or < 0 on error.
 */
int StreamAuditor::destroy()
{
  if (table_ != NULL) {
    mutex_.acquire();
    table_->destroy();
    operator delete(table_);

    streammap_->destroy();               //added by xlf 2014/7/28
    operator delete(streammap_);          //added by xlf 2014/7/28
    mutex_.release();
    table_ = NULL;
    streammap_=0;                        //added by xlf 2014/7/28
  }

  return 0;
}

//! Dump object.
void StreamAuditor::dump(std::ostream &os) const
{
  os << "[StreamAuditor]\t";
  os << "\tStream table ";
  table_->dump(os);
  os << '/' << max_stream_ << '\t';
  os << "stream timeout (seconds): " << stream_timeout_ << '\t';
  os << "syn/fin/repeat: " << syn_ << '/' << fin_ << '/' << repeat_ << '\t';
  dissector_.port_changed().dump(os);
}

void StreamAuditor::dump_stream(std::ostream &os, int param, int service, uint32_t sip, uint32_t dip, int sport, int dport) const
{
  time_t n = time(NULL);
  mutex_.acquire();
  os << "stream jump size: " << jump_table_.size() << std::endl;
  std::map<StreamKey, std::vector<Stream> >::const_iterator jumpit = jump_table_.begin();

  for (int i = 0; jumpit != jump_table_.end(); ++jumpit, ++i) {
    os << " " << i << ") " << jumpit->first << std::endl;
    std::vector<Stream>::const_iterator vit = jumpit->second.begin();

    for (; vit != jumpit->second.end(); ++vit) {
      os << "\t" << vit->key << "\t" << vit->sid << '\t' << vit->service << '\t' << vit->account << std::endl;
    }
  }

  std::map<StreamKey, Stream *> &smap = table_->map();
  os << " stream table size: " << smap.size() << std::endl;
  std::map<StreamKey, Stream *>::const_iterator cit = smap.begin();
  os << " index :\tsource\t\t->\tdestination\t\tsession_ID\t\tlive service\tstat\taccount\n";
  os << " -----  \t------\t\t  \t-----------\t\t----------\t\t---- -------\t----\t-------\n";

  for (int i = 0; cit != smap.end() && i < 102400; cit++, i++) {
    if (param != 0  && service != 0 && cit->second->service == service) {
      continue;
    }

    os << " " << i << ":\t" << cit->first << "\t";
    os << cit->second->sid << '\t' << n - cit->second->live << '\t';

    if (ServiceDef::service2name(cit->second->service) != NULL) {
      os << ServiceDef::service2name(cit->second->service) << '\t';
    } else {
      os << cit->second->service << '\t';
    }

    switch (cit->second->stat) {
    case 0:
      os << "N/A";
      break;

    case TCP_SYN_SENT:
      os << "SYN";
      break;

    case TCP_ESTABLISHED:
      os << "EST";
      break;

    default:
      os << "INV";
      break;
    }

    if (cit->second->flag == 1) {
      os << "_D";
    }

    os << '\t' << cit->second->account << std::endl;
  }

  mutex_.release();
}

void StreamAuditor::dump_stream_ini(std::ostream &os) const
{
  int i = 0;
  mutex_.acquire();
  os << "#TCP session dump.";
  os << "\tmax sessions: " << max_stream_;
  os << "\tsession count: " << table_->map().size() + jump_table_.size() << std::endl << std::endl;
  //os << "[Session_Total]\n\tsession_total=" << table_->map().size() + jump_table_.size() << endl << endl;
  struct tm t;
  char tmp[32] = {0};
  std::map<StreamKey, std::vector<Stream> >::const_iterator jumpit = jump_table_.begin();

  for (; jumpit != jump_table_.end(); ++jumpit) {
    //os << " " << i << ") " << jumpit->first << endl;
    std::vector<Stream>::const_iterator vit = jumpit->second.begin();

    for (; vit != jumpit->second.end(); ++vit) {
      os << "[Session_" << ++i << "]" << std::endl;
      localtime_r(&vit->begin.tv_sec, &t);
      os << "\tStartTime=" << t.tm_year + 1900 << '-' << t.tm_mon + 1 << '-' << t.tm_mday \
         << ' ' << t.tm_hour << ':' << t.tm_min << ':' << t.tm_sec << std::endl;
      localtime_r((time_t *) & (vit->live), &t);
      os << "\tActiveTime=" << t.tm_year + 1900 << '-' << t.tm_mon + 1 << '-' << t.tm_mday \
         << ' ' << t.tm_hour << ':' << t.tm_min << ':' << t.tm_sec << std::endl;
      os << "\taccount=" << vit->account << std::endl;
      os << "\tsource_ip=" << CIDR::ntos(vit->key.saddr, tmp, sizeof(tmp) - 1) << std::endl;
      os << "\tdest_ip=" << CIDR::ntos(vit->key.daddr, tmp, sizeof(tmp) - 1) << std::endl;
      os << "\tsource_port=" << ntohs(vit->key.sport) << std::endl;
      os << "\tdest_port=" << ntohs(vit->key.dport) << std::endl;
      os << "\tservice=" << vit->service << std::endl;
      os << "\tsid=" << vit->sid << std::endl;
      os << "\tbytes=" << vit->bytes << std::endl;
      os << "\tpackets=" << vit->packets << std::endl;
      os << "\trecords=" << vit->records << std::endl << std::endl;
    }
  }

  std::map<StreamKey, Stream *> &smap = table_->map();
  std::map<StreamKey, Stream *>::const_iterator cit = smap.begin();

  for (; cit != smap.end() && i < 102400; cit++) {
    if (cit->second->service == 1) {
      continue;
    }

    os << "[Session_" << ++i << "]" << std::endl;
    localtime_r(&cit->second->begin.tv_sec, &t);
    os << "\tStartTime=" << t.tm_year + 1900 << '-' << t.tm_mon + 1 << '-' << t.tm_mday \
       << ' ' << t.tm_hour << ':' << t.tm_min << ':' << t.tm_sec << std::endl;
    localtime_r((time_t *) & (cit->second->live), &t);
    os << "\tActiveTime=" << t.tm_year + 1900 << '-' << t.tm_mon + 1 << '-' << t.tm_mday \
       << ' ' << t.tm_hour << ':' << t.tm_min << ':' << t.tm_sec << std::endl;
    os << "\taccount=" << cit->second->account << std::endl;
    os << "\tsource_ip=" << CIDR::ntos(cit->second->key.saddr, tmp, sizeof(tmp) - 1) << std::endl;
    os << "\tdest_ip=" << CIDR::ntos(cit->second->key.daddr, tmp, sizeof(tmp) - 1) << std::endl;
    os << "\tsource_port=" << ntohs(cit->second->key.sport) << std::endl;
    os << "\tdest_port=" << ntohs(cit->second->key.dport) << std::endl;
    os << "\tservice=" << cit->second->service << std::endl;
    os << "\tsid=" << cit->second->sid << std::endl;
    os << "\tbytes=" << cit->second->bytes << std::endl;
    os << "\tpackets=" << cit->second->packets << std::endl;
    os << "\trecords=" << cit->second->records << std::endl << std::endl;
  }

  mutex_.release();
  os << "[Session_Total]\n\tsession_total=" << i << std::endl;
}

void StreamAuditor::dump_stream_xml(std::ostream &os) const
{
  os << "xml";
}

void StreamAuditor::dump_mac(std::ostream &os) const
{
  char smac[20] = {0};
  char dmac[20] = {0};
  mutex_.acquire();
  std::map<StreamKey, Stream *> &smap = table_->map();
  os << " stream table size: " << smap.size() << std::endl;
  std::map<StreamKey, Stream *>::const_iterator cit = smap.begin();
  os << " index :\t\tsource -> destination\tsmac -> dmac\tsession ID\n";

  for (int i = 0; cit != smap.end() && i < 102400; cit++, i++) {
    os << " " << i << ":\t" << cit->first << "\t";
    os << CIDR::mac2str((uint8_t *)cit->second->mac, smac, sizeof(smac)) << " -> ";
    os << CIDR::mac2str((uint8_t *)cit->second->mac + 6, dmac, sizeof(dmac)) << "\t";
    os << cit->second->sid << std::endl;
  }

  mutex_.release();
}

/*!
 * Thread entry.
 * @return 0 on success or < 0 on error.
 */
//int StreamAuditor::svc(void)
//{
//  int ret = 0;
//  Frame *frame = NULL;
//  ThreadFIFO<Frame *> *fifo = classifier_.fifo(0);
//
//  if (fifo == NULL) {
//    return -1;
//  }
//
//  while (1) {
//    ret = fifo->read(frame);
//
//    if (frame == NULL) {
//      sleep(1);
//      continue;
//    }
//
//    mutex_.acquire();
//    ret = entry_streams(*frame);
//    mutex_.release();
//    classifier_.tcp_queue().free(frame);
//    frame = NULL;
//  }
//
//  return 0;
//}

void StreamAuditor::child(pid_t parent)
{
	 int ret = 0;
	  //Frame *frame = NULL;
	  //ThreadFIFO<Frame *> *fifo = classifier_.fifo(0);      //modified by xlf  2014/7/21
	 my_berkeleyDBbased_fifo<Frame>* fifo=classifier_.auditor_fifo();        //modified by xlf  2014/7/22
      Frame frame;
	  if (fifo == NULL) {
	    return ;
	  }

	  while (1) {
	    //ret = fifo->read(frame);
		  ret=fifo->pop_front(frame);   //modified by xlf  2014/7/21
	    if (ret!=0) {
	      sleep(1);
	      continue;
	    }
        sleep(1);
	    mutex_.acquire();
	    ret = entry_streams(frame);
	    mutex_.release();
	    //classifier_.tcp_queue().free(frame);       //modified by xlf 2014/7/21
	    //Frame = NULL;
	  }
}
int  StreamAuditor::prepare(ACE_Process_Options& options)
{
	ACE_DEBUG((LM_INFO, " StreamAuditor  prepare build.\n"));
	return 0;
}

int StreamAuditor::entry_streams(const Frame &frame)
{
  int ret = 0;
  StreamKey key = {0};

  if (key.copy(frame) < 0) {
    return -1;
  }

  const struct tcphdr *tcph = frame.tcphdr();

  if (tcph == NULL) {
    return -1;
  }

#if 0
  ACE_DEBUG((LM_DEBUG, " StreamAuditor: %s:%d->%s:%d\n", CIDR::ntos(key.saddr),
             ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
#endif

  if (tcph->syn) {
#if 0
    ACE_DEBUG((LM_DEBUG, " StreamAuditor:%s:%d->%s:%d[syn]\n", CIDR::ntos(key.saddr),
               ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
#endif

    if (tcph->ack) {
      key.reverse();  // modify the direct of stream.
    }

    if (/*table_->find(key) */streammap_->find(key)!= NULL) {
      repeat_++;
    } else {
#if 0
      ACE_DEBUG((LM_DEBUG, "StreamAuditor:%s:%d->%s:%d[syn][new_stream]\n", CIDR::ntos(key.saddr),
                 ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
#endif
      ret = new_stream(frame, key);
    }
  } else if (tcph->fin) {// If FIN, set a STATUS. not erase it.
#if 0
    ACE_DEBUG((LM_DEBUG, "StreamAuditor:%s:%d->%s:%d[fin]\n", CIDR::ntos(key.saddr),
               ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
#endif
   // Stream **stream = table_->find(key);
   Stream* stream=streammap_->find(key);
    // Just check stream == NULL or not. check *stream will wast time.
//    if (stream != NULL || (stream = table_->find(key.reverse())) != NULL) {
//      (*stream)->live = frame.ts.tv_sec;
//      fin_stream(**stream);//TODO
//      table_->free(*stream);
//      table_->erase(key);
//      fin_++;
//    }
       if (stream != NULL || (stream = streammap_->find(key.reverse())) != NULL) {
         stream->live = frame.ts.tv_sec;
         fin_stream(*stream);//TODO
         streammap_->erase(key);
         fin_++;
       }
  } else if (tcph->rst) {// RST
#if 0
    ACE_DEBUG((LM_DEBUG, "StreamAuditor:%s:%d->%s:%d[rst]\n", CIDR::ntos(key.saddr),
               ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
#endif

    if (tcph->window == htons(5840)) {
      ACE_DEBUG((LM_DEBUG, "%s:%d->%s:%d[rst][window]==htons(5840)\n", CIDR::ntos(key.saddr),
                 ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
      return 0;
    }

   // Stream **stream = table_->find(key);
      Stream* stream=streammap_->find(key);
    // Just check stream == NULL or not. check *stream will wast time.
//    if (stream != NULL || (stream = table_->find(key.reverse())) != NULL) {
//      (*stream)->live = frame.ts.tv_sec;
//      fin_stream(**stream);//TODO
//      table_->free(*stream);
//      table_->erase(key);
//      fin_++;
//    }
          if (stream != NULL || (stream = streammap_->find(key.reverse())) != NULL) {
            stream->live = frame.ts.tv_sec;
            fin_stream(*stream);//TODO
            table_->erase(key);
            fin_++;
          }
  } else {// Just process data.
    //Stream **stream = table_->find(key);
      Stream* stream=streammap_->find(key);
    // Just check stream == NULL or not. check *stream will wast time.
    if (stream != NULL || (stream = streammap_->find(key.reverse())) != NULL) {
#if 0
      ACE_DEBUG((LM_DEBUG, "StreamAuditor:%s:%d->%s:%d. stream != null.\n", CIDR::ntos(key.saddr),
                 ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));
#endif
      stream->live = frame.ts.tv_sec;
      stream->bytes += frame.caplen;
      stream->packets ++;

      // check repeat frame judged by TCP seq and ack_seq;
      if (key.saddr == frame.iphdr()->saddr) {
        if (stream->seq == frame.tcphdr()->seq) {
          stream->flag = 1;
          return 0;
        }

        stream->seq = frame.tcphdr()->seq;
      } else {
        if (stream->ack_seq == frame.tcphdr()->seq) {
          stream->flag = 1;
          return 0;
        }

        stream->ack_seq = frame.tcphdr()->seq;
      }

      stream->stat = TCP_ESTABLISHED;

      if ((ret = dissector_.dissect(*stream, frame)) > 0) {
#if 0
        ACE_DEBUG((LM_DEBUG, "StreamAuditor dissector_.dissect:%s:%d->%s:%d. ret=%d "
                   "stream != null.\n", CIDR::ntos(key.saddr),
                   ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport), ret));
#endif
        check_telnet_jump(*stream, frame, ret);
        audit_transaction(*stream, ret);
      }

      if (dissector_.trans_num_ > 0) {
        audit_more_transaction(*stream);
        dissector_.trans_num_ = 0;
      }
    } else {
      ACE_DEBUG((LM_DEBUG, "StreamAuditor:%s:%d->%s:%d. new stream.\n", CIDR::ntos(key.saddr),
                 ntohs(key.sport), CIDR::ntos(key.daddr), ntohs(key.dport)));

      // has push means has data. If not has stream then new one.
      // attention the key direction.
      if (tcph->psh) {
        if (ServiceDef::find(ntohs(key.dport)) > 0) {
          ret = new_stream(frame, key);
        }
      }
    }
  }

  return 0;
}

int StreamAuditor::new_stream(const Frame &frame, const StreamKey &key)
{
  Stream stream;


  memset(&stream, 0, sizeof(Stream));
  stream.sid = StreamID_Single::instance()->sid();
  stream.devid = classifier_.device_id;
  stream.trans.sid = stream.sid;
  stream.trans.direct = ORMTransaction::DIRECT_UP;
  stream.trans.sip = key.saddr;
  stream.trans.sport = key.sport;
  stream.trans.dip = key.daddr;
  stream.trans.dport = key.dport;
  stream.trans.protocol = 6;	// TCP
  stream.key = key;

  if (key.saddr == frame.iphdr()->saddr) {
    stream.seq = frame.tcphdr()->seq;
    stream.ack_seq = frame.tcphdr()->ack_seq;
  } else {
    stream.seq = frame.tcphdr()->ack_seq;
    stream.ack_seq = frame.tcphdr()->seq;
  }

  stream.stat = TCP_SYN_SENT;
  memcpy(&stream.begin, &frame.ts, sizeof(struct timeval));
  memcpy(&stream.trans.ts, &frame.ts, sizeof(struct timeval));
  stream.live = frame.ts.tv_sec;
  // Check whether key is the same direction with frame.
  const struct iphdr *iph = frame.iphdr();

  if (iph->saddr == key.saddr) {	// up
    memcpy(stream.mac, frame.pkt + 6, 6);
    memcpy(stream.mac + 6, frame.pkt, 6);
  } else {
    memcpy(stream.mac, frame.pkt, sizeof(stream.mac));
  }

  //! chech port changed.
  PeerKey peer_key(stream.key.daddr, stream.key.dport);
  dissector_.port_changed().find(peer_key, stream.service);

  if (stream.service == 0) {
    //dispatcher_.find_gather_policy(key, stream->service);
	  stream.service=80;
  }

  stream.trans.service = stream.service;
  int ret = 0;
  if ((ret = /*table_->insert(key, stream)*/
		  streammap_->insert((StreamKey&)key,(Stream&)stream)) == 0) {
    // Write the stream to audit outputer when it should be audit.
    if (stream.service >= ServiceDef::SERVICE_OTHER) {
      audit_stream(stream, ORMStream::SESSION_BEGIN);
    }

    syn_++;
  } else {
    repeat_++;
  }

  return ret;
}

int StreamAuditor::fin_stream(Stream &stream)
{
  fin_telnet_jump(stream);

  //yxd add begin
  if (stream.private_data) {
    delete[] stream.private_data;
    stream.private_data = 0;
  }

  //yxd add end;
  // if stream.trans.data not empty, should record it first.
  if (stream.trans.data_len > 0) {
    audit_transaction(stream, 1);
  }

  if (stream.service != ServiceDef::SERVICE_FTP && strlen(stream.response) > 0) {
    audit_transaction(stream, 2);
  }

  if (stream.service >= ServiceDef::SERVICE_OTHER) {
    return audit_stream(stream, ORMStream::SESSION_END);
  }

  return 0;
}

int StreamAuditor::clean_stream()
{
  time_t now = time(NULL);
  int smap_erase = 0;
  mutex_.acquire();
  std::map<StreamKey, Stream *> &smap = table_->map();
  std::map<StreamKey, Stream *>::iterator it = smap.begin();

  for (int i = 0; it != smap.end() && i < max_stream_; i++) {
    // if the stream is telnet, rlogin or ssh, the STREAM_TIMEOUT should be 20 times.
    if (now - it->second->live >
        (it->second->service == ServiceDef::SERVICE_TELNET || it->second->service == ServiceDef::SERVICE_RLOGIN || it->second->service == ServiceDef::SERVICE_SSH ? stream_timeout_ * 10 : stream_timeout_)) {
      fin_stream(*it->second);
      //table_->free(it->second);
      smap.erase(it++);
      smap_erase ++;
    } else {
      ++it;
    }
  }

  mutex_.release();
  dissector_.port_changed().clean();
  ACE_DEBUG((LM_DEBUG, " StreamAuditor: clean timeout streams: %d\n", smap_erase));
  return 0;
}

int StreamAuditor::audit_stream(const Stream &stream, int flag) const
{
  // Write the stream to audit outputer.
  ORMEntity *entity = classifier_.output_queue().malloc();

  if (entity == NULL) {
    return -1;
  }

  entity->type = ORMEntity::STREAM;
  entity->un.stream.eventtype = flag;	// ORMStream::SESSION_END or SESSION_BEGIN;
  stream.stream2orm(entity->un.stream);
  entity->len = entity->un.stream.length();

  if (classifier_.output_queue().write(entity) < 0) {
    classifier_.output_queue().free(entity);
    return -1;
  } else {
    ACE_DEBUG((LM_DEBUG, " StreamAuditor:%s:%d->%s:%d[audit_stream]\n",
               CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
               CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
  }

  return 0;
}

int StreamAuditor::audit_transaction(Stream &stream, int flag) const
{
  ORMEntity *entity = NULL;
  my_berkeleyDBbased_fifo<ORMEntity>* fifo=classifier_.output_fifo();
  if (flag >= Dissector::RET_ACCOUNT) {
    flag -= Dissector::RET_ACCOUNT;
    strncpy(stream.trans.account, stream.account, sizeof(stream.trans.account));
    audit_stream(stream, ORMStream::SESSION_UPDATE);
  }

  if (flag == 1 || flag == 3) {
    {
      stream.records ++;
      stream.trans.seq ++;
    }
    entity = classifier_.output_queue().malloc();

    if (entity == NULL) {
      return -1;
    }

    entity->type = ORMEntity::TRANSACTION;
    entity->un.trans.copy(stream.trans);
    entity->un.trans.tcp_seq = stream.seq;
    entity->un.trans.tcp_ack_seq = stream.ack_seq;
    stream.trans.operate[0] = '\0';
    stream.trans.object[0] = '\0';
    stream.trans.result[0] = '\0';
    stream.trans.data[0] = '\0';
    stream.trans.data_len = 0;
    entity->len = entity->un.trans.length();

    if (/* classifier_.output_queue().write(entity) */fifo->push_back(*entity)< 0) {
      classifier_.output_queue().free(entity);
      ACE_DEBUG((LM_ERROR, " StreamAuditor: %s:%d->%s:%d[audit_transaction] write output_queue failed.\n",
                 CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
                 CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
      return -1;
    } else {
      ACE_DEBUG((LM_DEBUG, " StreamAuditor: %s:%d->%s:%d[audit_transaction] write succeed.\n",
                 CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
                 CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
    }
  }

  if (flag == 2 || flag == 3) {
    {
      stream.records ++;
      stream.trans.seq ++;
    }
    entity = classifier_.output_queue().malloc();

    if (entity == NULL) {
      return -1;
    }

    entity->type = ORMEntity::TRANSACTION;
    stream.response2transaction(entity->un.trans);
    stream.response[0] = '\0';
    entity->len = entity->un.trans.length();

    if (/* classifier_.output_queue().write(entity) */fifo->push_back(*entity) < 0) {
      classifier_.output_queue().free(entity);
      ACE_DEBUG((LM_ERROR, " StreamAuditor: %s:%d->%s:%d[audit_transaction] write output_queue failed.\n",
                 CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
                 CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
      return -1;
    } else {
      ACE_DEBUG((LM_DEBUG, " StreamAuditor: %s:%d->%s:%d[audit_transaction] write succeed.\n",
                 CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
                 CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
    }
  }
  classifier_.output_queue().free(entity);
  return 0;
}

//! audit more transaction.
int StreamAuditor::audit_more_transaction(Stream &stream)
{
  ORMEntity *entity = NULL;

  for (int i = 0; i < dissector_.trans_num_; i++) {
    entity = classifier_.output_queue().malloc();

    if (entity == NULL) {
      return -1;
    }

    entity->type = ORMEntity::TRANSACTION;
    entity->un.trans.copy(dissector_.trans_[i]);
    dissector_.trans_[i].operate[0] = '\0';
    dissector_.trans_[i].object[0] = '\0';
    dissector_.trans_[i].result[0] = '\0';
    dissector_.trans_[i].data[0] = '\0';
    dissector_.trans_[i].data_len = 0;
    entity->len = entity->un.trans.length();

    if (classifier_.output_queue().write(entity) < 0) {
      classifier_.output_queue().free(entity);
      ACE_DEBUG((LM_ERROR, " StreamAuditor: %s:%d->%s:%d[audit_transaction] write output_queue failed.\n",
                 CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
                 CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
      return -1;
    } else {
      ACE_DEBUG((LM_DEBUG, " StreamAuditor: %s:%d->%s:%d[audit_transaction] write succeed.\n",
                 CIDR::ntos(stream.trans.sip), ntohs(stream.trans.sport),
                 CIDR::ntos(stream.trans.dip), ntohs(stream.trans.dport)));
    }
  }

  return 0;
}

int StreamAuditor::check_telnet_jump(const Stream &stream, const Frame &frame, int flag)
{
  // check jump or exit.
  if (flag % 2 == 1) {	// means ORMTransaction         //flag  1 2
    if ((strcmp(stream.trans.operate, "telnet") == 0)
        || (strcmp(stream.trans.operate, "rlogin") == 0)) {
      std::map<StreamKey, std::vector<Stream> >::iterator it = jump_table_.find(stream.key);

      if (it == jump_table_.end()) {
        std::vector<Stream> vs;
        Stream s = stream;
        //s.account[0] = '\0';
        s.sid = StreamID_Single::instance()->sid();
        s.trans.sid = s.sid;
        s.trans.direct = ORMTransaction::DIRECT_UP;
        memcpy(&s.begin, &frame.ts, sizeof(struct timeval));
        memcpy(&s.trans.ts, &frame.ts, sizeof(struct timeval));
        s.live = frame.ts.tv_sec;
        s.key.daddr = inet_addr(stream.trans.object);
        audit_stream(s, ORMStream::SESSION_BEGIN);
        vs.push_back(s);
        jump_table_[stream.key] = vs;
      } else {
        Stream s = stream;
        s.key.daddr = inet_addr(stream.trans.object);
        it->second.push_back(s);
      }
    } else if (strcmp(stream.trans.operate, "exit") == 0) {
      std::map<StreamKey, std::vector<Stream> >::iterator it = jump_table_.find(stream.key);

      if (it != jump_table_.end()) {
        if (!it->second.empty()) {
          audit_stream(it->second.back(), ORMStream::SESSION_END);
        }

        it->second.pop_back();

        if (it->second.empty()) {
          jump_table_.erase(stream.key);
        }
      }
    }
  }

  std::map<StreamKey, std::vector<Stream> >::iterator it = jump_table_.find(stream.key);

  if (it != jump_table_.end()) {
    for (size_t i = 0; i < it->second.size(); i++) {
      if (it->second[i].service > 1) {
        it->second[i].trans.copy(stream.trans);
        it->second[i].trans.sid = it->second[i].sid;
        strncpy(it->second[i].response, stream.response, sizeof(stream.response));
        audit_transaction(it->second[i], flag);
      } else {
        break;
      }
    }
  }

  return 0;
}

int StreamAuditor::fin_telnet_jump(const Stream &stream)
{
  std::map<StreamKey, std::vector<Stream> >::iterator it = jump_table_.find(stream.key);

  if (it != jump_table_.end()) {
    const size_t num = it->second.size();

    for (size_t i = 0; i < num; i++) {
      // if stream.trans.data not empty, should record it first.
      if (it->second[i].trans.data_len > 0) {
        audit_transaction(it->second[i], 1);
      }

      if (strlen(it->second[i].response) > 0) {
        audit_transaction(it->second[i], 2);
      }

      audit_stream(it->second[i], ORMStream::SESSION_END);
    }

    jump_table_.erase(it);
    return 0;
  }

  return -1;
}

