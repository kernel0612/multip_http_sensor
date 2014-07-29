#include "PortChanged.h"
#include "Stream.h"
#include "CIDR.h"
#include <iostream>

#ifndef _WIN32
#include <arpa/inet.h>
#endif



int PortChanged::insert(const PeerKey &key, int service)
{
  m_port_mutex_.acquire();
  change_mport_[key] = service;
  m_port_mutex_.release();
  return 0;
}

int PortChanged::erase(const PeerKey &key)
{
  m_port_mutex_.acquire();
  change_mport_.erase(key);
  m_port_mutex_.release();
  return 0;
}

int PortChanged::find(const PeerKey &key, int &service) const
{
  int ret = 0;
  service = 0;
  m_port_mutex_.acquire();
  std::map<PeerKey, int>::const_iterator cit = change_mport_.find(key);

  if (cit == change_mport_.end()) {
    ret = -1;
  } else {
    service = cit->second;
  }

  m_port_mutex_.release();
  return ret;
}

// There is a bug. may be the new change port is erased.
int PortChanged::clean()
{
  m_port_mutex_.acquire();
  std::map<PeerKey, int>::iterator it = change_mport_.begin();

  for (; it != change_mport_.end();) {
    change_mport_.erase(it++);
  }

  m_port_mutex_.release();
  ftp_mutex_.acquire();
  ftp_mport_.clear();
  ftp_mutex_.release();
  return 0;
}

void PortChanged::dump(std::ostream &os) const
{
  m_port_mutex_.acquire();
  os << "changed ports have " << change_mport_.size() << std::endl;
  std::map<PeerKey, int>::const_iterator cit = change_mport_.begin();

  for (; cit != change_mport_.end(); ++cit) {
    os << "\n\t" << CIDR::ntos(cit->first.addr) << ':' << ntohs(cit->first.port) << " with service " << cit->second;
  }

  m_port_mutex_.release();
  os << std::endl;
}

