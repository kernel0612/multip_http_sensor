#ifndef __MAP_H
#define __MAP_H

#include <iostream>
#include <map>

/*!
 * @brief The class defines map wrapper.
 */
template <class Key, class T>
class PMap
{
private:
  typedef typename std::map<Key, T>::value_type value_type;
  typedef typename std::map<Key, T>::iterator map_it;
  typedef typename std::map<Key, T>::const_iterator map_cit;

public:
  //! Define default size.
  enum  	{ DEFAULT_SIZE = 1024 };

  PMap() {}
  PMap(int size) {}
  ~PMap() {}

  //! Search key in table.
  T *find(const Key &key);

  //! Insert key into map.
  int insert(const Key &key, const T &t);

  //! Erase key from map.
  int erase(const Key &key) {
    return map_.erase(key);
  }

  //! dump information.
  void dump(std::ostream &os) const;

  //! get map object.
  std::map<Key, T> &map() {
    return map_;
  }
  const std::map<Key, T> &const_map() const {
    return map_;
  }

protected:
  //! map.
  std::map<Key, T> map_;
};


/*!
 * Search key in map
 * @param key
 * @return 0 on success and < 0 on error.
 */
template <class Key, class T>
T *PMap<Key, T>::find(const Key &key)
{
  map_it it = map_.find(key);

  if (it == map_.end()) {
    return NULL;
  }

  return &(it->second);
}

/*!
 * Insert key and T into map.
 * @param key
 * @param t
 * @return 0 on success and < 0 on error.
 */
template <class Key, class T>
int PMap<Key, T>::insert(const Key &key, const T &t)
{
  if (map_.find(key) != map_.end()) {
    return -1;
  }

  map_.insert(value_type(key, t));
  return 0;
}

/*!
 * Dump map information.
 */
template <class Key, class T>
void PMap<Key, T>::dump(std::ostream &os) const
{
  os << "map size/max_size: " << map_.size() << '/' << map_.max_size() << std::endl;
  map_cit cit = map_.begin();

  for (int i = 0; cit != map_.end() && i < 102400; cit++, i++) {
    os << " " << i << ":\t\t" << cit->first << "\t" << cit->second << std::endl;
  }
}

#endif //__MAP_H

