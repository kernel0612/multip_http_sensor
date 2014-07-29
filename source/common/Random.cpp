#include "Random.h"
#include <fstream>
#include <cstring>
#include <cstdlib>

Random::~Random()
{
  std::ofstream ofs(this->file_);

  if (ofs.is_open()) {
    ofs << this->seed_;
    ofs.close();
  }
}

void Random::file(const char *pfile)
{
  strncpy(file_, pfile, sizeof(file_));
}

int Random::bigendian()
{
  int i = 0x12345678;

  if (*(char *)&i == 0x12)	{
    return 1;
  }

  return 0;
}

int Random::init(int devid, int devnum, const char *pfile)
{
  this->devid_ = devid;
  this->devnum_ = devnum;
  strncpy(file_, pfile, sizeof(file_));

  // Only surpport less 256 SS number.
  if (this->devnum_ >= 256) {
    return -1;
  }

  if (this->devid_ > this->devnum_) {
    return -1;
  }

  std::ifstream ifs(this->file_);

  if (ifs.is_open()) {
    ifs >> this->seed_;
    ifs.close();
    this->seed_ += 2000;	// Add 2000 to seed_.
  } else {
    srand((uint32_t)time(NULL));
    char *p = (char *)&this->seed_;
    int r = ::rand();
    memcpy(p, &r, 4);
    r = ::rand();
    memcpy(p + 4, &r, 4);
  }

  int offset = 0;

  if (this->devnum_ < 128) {	//The SS number is smaller than 128, use one char.
    if (bigendian() == 1) {
      offset = 0;  // Big endian
    } else {
      offset = 7;
    }

    char *p = (char *)&this->seed_;
    memset(p + offset, 0, 1);
    *(p + offset) = (char)this->devid_;
    p = (char *)&this->min_;
    memset(p, 0, sizeof(int64_t));
    *(p + offset) = (char)this->devid_;
    p = (char *)&this->max_;
    memset(p, 0xff, sizeof(int64_t));
    memset(p + offset, 0, 1);
    *(p + offset) = (char)this->devid_;
  } else if (this->devnum_ >= 128) {	// The SS number is bigger than 128, use two char.
    if (bigendian() == 1) {
      offset = 0;  // Big endian
    } else {
      offset = 6;
    }

    char *p = (char *)&this->seed_;
    memset(p + offset, 0, 2);
    *(short *)(p + offset) = (short)this->devid_;
    p = (char *)&this->min_;
    memset(p, 0, sizeof(int64_t));
    *(short *)(p + offset) = (short)this->devid_;
    p = (char *)&this->max_;
    memset(p, 0xff, sizeof(int64_t));
    memset(p + offset, 0, 2);
    *(short *)(p + offset) = (short)this->devid_;
  }

  // then write back the seed.
  std::ofstream ofs(this->file_);

  if (ofs.is_open()) {
    ofs << this->seed_;
    ofs.close();
  }

  return 0;
}

int64_t Random::rand()
{
  if (this->seed_ >= this->max_ - 1) {
    this->seed_ = this->min_ + 1;
  } else if (this->seed_ % 1000 == 0) {	// every 1000 times write back to file.
    std::ofstream ofs(this->file_);

    if (ofs.is_open()) {
      ofs << this->seed_;
      ofs.close();
    }
  }

  return ++this->seed_;
}

int Random::get_devid(int64_t r) const
{
  char *p = (char *)&r;
  int offset = 0;

  if (this->devnum_ < 128) {	//The SS number is smaller than 128, use one char.
    if (bigendian() == 1) {
      offset = 0;  // Big endian
    } else {
      offset = 7;
    }

    char n = *(p + offset);
    return (int)n;
  } else {
    if (bigendian() == 1) {
      offset = 0;  // Big endian
    } else {
      offset = 6;
    }

    short sh = *(short *)(p + offset);
    return (int)sh;
  }
}

void Random::dump(std::ostream &os) const
{
  os << "Random, devid/devnum " << this->devid_ << '/' << this->devnum_ << " ";
  os << this->min_ << " -> " << this->max_ << '\t';
  os << this->file_ << "\t seed:" << this->seed_ << std::endl;
}

