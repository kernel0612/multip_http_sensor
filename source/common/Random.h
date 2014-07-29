#ifndef __RANDOM_H
#define __RANDOM_H

#include <string>
#include <iostream>
#include <stdint.h>

/*!
 * @brief The class defines int64_t random.
 */
class Random
{
public:
  Random() : \
    devid_(0), devnum_(0), seed_(0), max_(0), min_(0) {
    file_[0] = '\0';
  }
  ~Random();

public:
  int init(int devid, int devnum, const char *pfile);
  int64_t rand();
  void dump(std::ostream &os) const;

  const char *file() const {
    return file_;
  }
  inline void file(const char *pfile);
  int get_devid(int64_t r) const;

  int devid() const {
    return devid_;
  }
  int devnum() const {
    return devnum_;
  }

protected:
  static int bigendian();

private:
  int devid_;
  int devnum_;
  int64_t seed_;
  int64_t max_;
  int64_t min_;
  char file_[256];
};

#endif	//__RANDOM_H

