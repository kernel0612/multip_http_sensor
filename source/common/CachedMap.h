#ifndef __CACHED_MAP_H
#define __CACHED_MAP_H

#include "PMap.h"
#include <ace/Malloc_T.h>
#include <ace/Synch_Traits.h>
#include <ace/Thread_Mutex.h>

/*!
 * @brief The class defines chached map.
 */
template <class Key, class T>
class CachedMap : public PMap<Key, T *>
{
private:
  typedef PMap<Key, T *> _Parent;

public:
  //! Define default size.
  enum  	{ DEFAULT_SIZE = 1024 };

  CachedMap() : _Parent(DEFAULT_SIZE), capacity_(DEFAULT_SIZE) {}
  CachedMap(int size) : _Parent(size), capacity_(size) {}
  ~CachedMap() {}

  //! Create map object.
  int create();

  //! Destroy map object.
  int destroy();

  //! malloc a new T.
  T *malloc() {
    return (T *)mem_->malloc();
  }

  //! free T.
  void free(T *t) {
    mem_->free(t);
  }

  //! dump information.
  void dump(ostream &os) const;

protected:
  //! Capacity of map.
  const int capacity_;

  //! Cached memory for map.
  ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX> *mem_;
};


/*!
 * Create map memory and map.
 * @return 0 on success and < 0 on error.
 */
template <class Key, class T>
int CachedMap<Key, T>::create()
{
  mem_ = (ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX> *) operator new(sizeof(ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX>));

  try {
    new(mem_) ACE_Cached_Allocator<T, ACE_SYNCH_MUTEX>(capacity_);
  } catch (...) {
    operator delete(mem_);
    mem_ = NULL;
    ACE_DEBUG((LM_ERROR, " Cached_Map: new mem failed.\n"));
    throw;
    return -1;
  }

  return 0;
}

/*!
 * Destory map.
 * @return 0 on success and < 0 on error.
 */
template <class Key, class T>
int CachedMap<Key, T>::destroy()
{
  // for(map_) delete all items.
  // foreach map delete.  Can do verify
  //map_.clear();
  if (mem_ != NULL) {
    operator delete(mem_);
    mem_ = NULL;
  }

  return 0;
}

/*!
 * Dump map information.
 */
template <class Key, class T>
void CachedMap<Key, T>::dump(ostream &os) const
{
  //_Parent::dump(os);
  if (mem_ == NULL) {
    os << "Failed: not create the Cahced object.";
    return;
  }

  os << "free/capacity: " << mem_->pool_depth() << '/' << capacity_;
}

#endif

