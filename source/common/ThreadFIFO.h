#ifndef __THREAD_FIFO_H
#define __THREAD_FIFO_H

#include <iostream>
#include <ctime>
#include <stdint.h>
#include <ace/Thread.h>
#include <ace/Synch.h>
#include <ace/Condition_T.h>

/*!
 * @brief The class defines thread fifo.
 */
template<class T>
class ThreadFIFO
{
public:
  ThreadFIFO(int capacity = 0);
  ~ThreadFIFO();

  int create(int capacity = 0);
  int destroy();

  int read(T &data);
  int write(const T &data);
  int read_nonblk(T &data);
  int write_nonblk(const T &data);

  const int capacity() const {
    return capacity_;
  }
  const int total() const {
    return total_;
  }
  const int allin() const {
    return allin_;
  }
  const int allout() const {
    return allout_;
  }
  const int alldiscard() const {
    return alldiscard_;
  }
  const time_t start() const {
    return start_;
  }
  void dump(std::ostream &os) const;

private:
  int total_;   // total records in FIFO.
  uint64_t  allin_;   // all records going into FIFO.
  uint64_t  allout_;    // all records geting out of FIFO.
  uint64_t  alldiscard_;  // all records being discarded.
  time_t start_;    // start time.
  int in_;    // write pointer.
  int out_;   // read pointer.
  int capacity_;
  T *pvector_;
protected:
  mutable ACE_Thread_Mutex mutex_;
  ACE_Condition<ACE_Thread_Mutex> cond_;

};

template<class T>
ThreadFIFO<T>::ThreadFIFO(int capacity) : \
  total_(0), allin_(0), allout_(0), alldiscard_(0), start_(0), in_(0), out_(0), \
  capacity_(capacity), pvector_(NULL), cond_(this->mutex_)
{
}

template<class T>
ThreadFIFO<T>::~ThreadFIFO()
{
}

template<class T>
int ThreadFIFO<T>::create(int capacity /* = 0 */)
{
  if (capacity > 0) {
    this->capacity_ = capacity;
  }

  if (this->capacity_ == 0) {
    return -1;
  }

  try {
    this->pvector_ = new T[this->capacity_];
  } catch (...) {
    return -3;
  }

  this->start_ = time(NULL);
  return 0;
}

template<class T>
int ThreadFIFO<T>::destroy()
{
  if (this->pvector_ != NULL) {
    delete [] this->pvector_;
  }

  this->pvector_ = NULL;
  return 0;
}

template<class T>
int ThreadFIFO<T>::read(T &data)
{
  mutex_.acquire();

  while (this->in_ == this->out_ && this->total_ == 0) {
    cond_.wait();
  }

  data = this->pvector_[this->out_];

  if (++this->out_ == this->capacity_) {
    this->out_ = 0;
  }

  this->total_--;
  this->allout_++;
  mutex_.release();
  return 0;
}

template<class T>
int ThreadFIFO<T>::read_nonblk(T &data)
{
  if (this->total_ == 0) {
    return -2;
  }

  mutex_.acquire();

  while (this->in_ == this->out_ && this->total_ == 0) {
    cond_.wait();
  }

  data = this->pvector_[this->out_];

  if (++this->out_ == this->capacity_) {
    this->out_ = 0;
  }

  this->total_--;
  this->allout_++;
  mutex_.release();
  return 0;
}

// This function is not a block write. It is a non block write.
// I must use one more empty condition to do this.
template<class T>
int ThreadFIFO<T>::write(const T &data)
{
  mutex_.acquire();

  // Attention this. It must check whether the fifo is full. Otherwise will cause coredump.
  if (this->total_ == this->capacity_) {
    this->alldiscard_++;
    mutex_.release();
    return -2;
  }

  this->pvector_[this->in_] = data;

  if (++this->in_ == this->capacity_) {
    this->in_ = 0;
  }

  this->total_++;
  this->allin_++;
  cond_.signal();
  mutex_.release();
  return 0;
}

// This function has trouble, do not use it.
template<class T>
int ThreadFIFO<T>::write_nonblk(const T &data)
{
  if (this->total_ == this->capacity_) {
    this->alldiscard_++;
    return -2;
  }

  mutex_.acquire();
  this->pvector_[this->in_] = data;

  if (++this->in_ == this->capacity_) {
    this->in_ = 0;
  }

  this->total_++;
  this->allin_++;
  cond_.signal();
  mutex_.release();
  return 0;
}

template<class T>
void ThreadFIFO<T>::dump(std::ostream &os) const
{
  os << "FIFO's used/capacity=" << this->total_ << '/' << this->capacity_;
  os << ", in/out/discard=" << this->allin_ << '/' << this->allout_ << '/' << this->alldiscard_;
  //os << ", point(" << this->in_ << '/' << this->out_ << ")";
  os << ", start: ";
  char tmp[32] = {0};
  strftime(tmp, sizeof(tmp), "%F %T", localtime(&this->start_));
  os << tmp << std::endl;
}


#endif

