#ifndef __CACHED_FIFO_H
#define __CACHED_FIFO_H

#include "ThreadFIFO.h"
#include <ace/Malloc_T.h>
#include <ace/Synch_Traits.h>
#include <ace/Synch.h>

/*!
 * @brief The class defines cached FIFO, whitch use meomory and thread fifo.
 */
template <class T>
class CachedFIFO
{
public:
  enum { DEFAULT_SIZE = 1024 };
  CachedFIFO();
  CachedFIFO(int size);
  ~CachedFIFO() {}

  int create();
  int destroy();
  int capacity() const {
    return capacity_;
  }
  void dump(ostream &os) const;

  T *malloc() {
    return (T *)mem_->malloc(sizeof(T));
  }
  void free(T *data) {
    mem_->free(data);
  }
  int read(T **data) {
    *data = NULL;
    return fifo_.read(*data);
  }
  int write(const T *data) {
    return fifo_.write((T *)data);
  }
  int write_nonblk(const T *data) {
    return fifo_.write_nonblk((T *)data);
  }
  int write_malloc(const T *data);
  int write_nonblk_malloc(const T *data);

protected:
  const int capacity_;
  ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX> *mem_;
  ThreadFIFO<T *> fifo_;
};


template <class T>
CachedFIFO<T>::CachedFIFO() : capacity_(DEFAULT_SIZE), mem_(NULL), fifo_(DEFAULT_SIZE)
{
}

template <class T>
CachedFIFO<T>::CachedFIFO(int size) : capacity_(size), mem_(NULL), fifo_(size)
{
}

template <class T>
int CachedFIFO<T>::create()
{
  int ret = 0;

  if ((ret = fifo_.create()) < 0) {
    ACE_DEBUG((LM_ERROR, " Cached_FIFO: new fifo failed.\n"));
    return -1;
  }

  mem_ = (ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX> *) operator new(sizeof(ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX>));

  try {
    new(mem_) ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX>(capacity_);
  } catch (...) {
    operator delete(mem_);
    mem_ = NULL;
    ACE_DEBUG((LM_ERROR, " Cached_FIFO: new mem failed.\n"));
    throw;
    fifo_.destroy();
    return -1;
  }

  return 0;
}

template <class T>
int CachedFIFO<T>::destroy()
{
  fifo_.destroy();

  if (mem_ != NULL) {
    operator delete(mem_);
    mem_ = NULL;
  }

  return 0;
}

template <class T>
int CachedFIFO<T>::write_malloc(const T *data)
{
  T *t = (T *)mem_->malloc(sizeof(T));

  if (t == NULL) {
    return -1;
  }

  *t = *data;
  int ret = fifo_.write(t);

  if (ret < 0) {
    mem_->free(t);
  }

  return ret;
}

template <class T>
int CachedFIFO<T>::write_nonblk_malloc(const T *data)
{
  T *t = (T *)mem_->malloc(sizeof(T));

  if (t == NULL) {
    return -1;
  }

  *t = *data;
  int ret = fifo_.write_nonblk(t);

  if (ret < 0) {
    mem_->free(t);
  }

  return ret;
}

template <class T>
void CachedFIFO<T>::dump(ostream &os) const
{
  if (mem_ == NULL) {
    os << "Failed: not create the Cahced object.";
    return;
  }

  os << "Cached chunks free/capacity: " << (int)mem_->pool_depth() << '/' << capacity_;
  fifo_.dump(os << "\t");

  if (capacity_ != fifo_.total() + (int)mem_->pool_depth()) {
    os << "\tmemeory and fifo not equel, maybe something don't free memory.\n";
  }
}

#endif

