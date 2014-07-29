#include "GatherClassifier.h"

GatherClassifier::GatherClassifier()
  : device_id(0), buffer_size_(DEFAULT_SIZE), tcp_queue_(NULL), output_queue_(NULL)
{
}

GatherClassifier::GatherClassifier(int size)
  : device_id(0), buffer_size_(size), tcp_queue_(NULL), output_queue_(NULL)
{
}

int GatherClassifier::create()
{
  int ret = 0;
  /*
   * Create tcp frame buffer.
   */
  tcp_queue_ = (CachedFIFO<Frame> *) operator new(sizeof(CachedFIFO<Frame>));

  try {
    new(tcp_queue_) CachedFIFO<Frame>(buffer_size_);
  } catch (...) {
    operator delete(tcp_queue_);
    tcp_queue_ = NULL;
    ACE_DEBUG((LM_ERROR, " Audit: new tcp frame buffer failed: %d\n", ret));
    throw;
    return -1;
  }

  if ((ret = tcp_queue_->create()) < 0) {
    ACE_DEBUG((LM_ERROR, " Audit: create tcp frame buffer failed: %d\n", ret));
    return -1;
  }

  /*
   * Create output buffer.
   */
  output_queue_ = (CachedFIFO<ORMEntity> *) operator new(sizeof(CachedFIFO<ORMEntity>));

  try {
    new(output_queue_) CachedFIFO<ORMEntity>(buffer_size_);
  } catch (...) {
    operator delete(output_queue_);
    output_queue_ = NULL;
    ACE_DEBUG((LM_ERROR, " Audit: new output buffer failed: %d\n", ret));
    throw;
    return -1;
  }

  if ((ret = output_queue_->create()) < 0) {
    ACE_DEBUG((LM_ERROR, " Audit: create output buffer failed: %d\n", ret));
    return -1;
  }

  /*
   * Create auditor fifo.
   */
  //  for (int i = 0; i < 6; i++) {
  //    if ((ret = auditor_fifo_[i].create(buffer_size_)) < 0) {
  //      ACE_DEBUG((LM_ERROR, " Audit: create frame buffer failed: %d\n", ret));
  //      return -1;
  //    }
  //  }

  if ((ret = auditor_fifo_.create(buffer_size_)) < 0) {
    ACE_DEBUG((LM_ERROR, " Audit: create frame buffer failed: %d\n", ret));
    return -1;
  }

  _capted_fifo.set_db_name("capted_fifo.db");
  if((ret=_capted_fifo.init())!=0){
	  ACE_DEBUG((LM_ERROR,"Audit: create capted fifo failed.\n"));
	  return -1;
  }
  _output_fifo.set_db_name("output_fifo.db");
  if((ret=_output_fifo.init())!=0){
	  ACE_DEBUG((LM_ERROR,"Audit: create output fifo failed.\n"));
	  return -1;
  }
  _auditor_fifo.set_db_name("auditor_fifo.db");
  if((ret=_auditor_fifo.init())!=0){
	  ACE_DEBUG((LM_ERROR,"Audit: create auditor fifo failed.\n "));
	  return -1;
  }
  return 0;
}

int GatherClassifier::destroy()
{
  if (tcp_queue_ != NULL) {
    tcp_queue_->destroy();
    delete tcp_queue_;
    tcp_queue_ = NULL;
  }

  if (output_queue_ != NULL) {
    output_queue_->destroy();
    delete output_queue_;
    output_queue_ = NULL;
  }

  //  for (int i = 0; i < 6; i++) {
  //    auditor_fifo_[i].destroy();
  //  }
  auditor_fifo_.destroy();
  return 0;
}

int GatherClassifier::classify(const struct pcap_pkthdr &pkth, const uint8_t *pkt, int captor_id)
{
  // Also do UDP calssify.
  Frame *frame = tcp_queue_->malloc();

  if (frame == NULL) {
    return -1;
  }

  if (frame->copy(pkth, pkt) < 0) {
    tcp_queue_->free(frame);
    return -1;
  }

  //int ret = tcp_queue_->write_nonblk(frame);  //modified by xlf  2014/7/21
  int ret=_capted_fifo.push_back(*frame);   //added by xlf 2014/7/21
  if (ret < 0) {
    tcp_queue_->free(frame);
    return -1;
  }
  tcp_queue_->free(frame);
  return 0;
}

int GatherClassifier::dispatch(Frame *frame)
{
  // Base saddr, daddr, sport dport to auditor.
  //  int ret = auditor_fifo_[0].write(frame);
 // int ret = auditor_fifo_.write(frame);
	if(!frame){
		return -1;
	}
  int ret=_auditor_fifo.push_back(*frame);
  if (ret < 0) {
    return ret;
  }

  return 0;
}

void GatherClassifier::dump(std::ostream &os) const
{
  os << "[TCP queue]\t";
  tcp_queue_->dump(os);
  os << "[Output queue]\t";
  output_queue_->dump(os);
  os << "[Auditor 0 queue]\t";
  //  auditor_fifo_[0].dump(os);
  auditor_fifo_.dump(os);
}

