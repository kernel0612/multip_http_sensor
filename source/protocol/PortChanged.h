#ifndef __PORT_CHANGED_H
#define __PORT_CHANGED_H

#include <map>
#include "ace/Synch.h"

#include "Stream.h"

/*!
 * @brief The class defines tcp port changed such as oracle on windows and ftp data.
 */
class PortChanged
{
  typedef struct FTPFileInfo {
    StreamKey	key;
    int64_t	sid;
    time_t live;
    char file[256];
  } FTPFileInfo;

public:
  PortChanged() {}
  ~PortChanged() {}

  int insert(const PeerKey &key, int service);
  int erase(const PeerKey &key);
  int find(const PeerKey &key, int &service) const;
  int find_ftp(const PeerKey &key, int &service) const;
  int clean();
  void dump(std::ostream &os) const;

protected:
  //! Port change and it's mutex.
  //! Map is peer key and int means service.
  std::map<PeerKey, int> change_mport_;
  mutable ACE_Thread_Mutex m_port_mutex_;

  //! FTP File port map.
  std::map<PeerKey, FTPFileInfo> ftp_mport_;
  mutable ACE_Thread_Mutex ftp_mutex_;
};

#endif //__PORT_CHANGED_H

