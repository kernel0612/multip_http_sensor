#ifndef __SERVICE_DEF_H
#define __SERVICE_DEF_H

#include <ext/hash_map>
#include <map>
#include <string>
#include <stdint.h>

/*!
 * @brief NBA services defines. And map for service or service name.
 */
class ServiceDef
{
public:
  typedef struct _value_string {
    uint32_t	value;
    const char	*strptr;
  } value_string;

  enum {
    SERVICE_OTHER = 2, \
    SERVICE_FTP = 21, \
    SERVICE_TELNET = 23, \
    SERVICE_ORACLE = 1521, \
    SERVICE_SYBASE = 5000, \
    SERVICE_DB2 = 50000, \
    SERVICE_SQL = 1433, \
    SERVICE_HTTP = 80, \
    SERVICE_SMTP = 25, \
    SERVICE_POP3 = 110, \
    SERVICE_X11 = 6000, \
    SERVICE_SSH = 22, \
    SERVICE_REXEC = 512, \
    SERVICE_RLOGIN = 513, \
    SERVICE_RSH = 514, \
    SERVICE_INFORMIX = 1526, \
    SERVICE_TERADATA = 1025, \
    SERVICE_DOMINO = 1352, \
    SERVICE_RDP = 3389, \
    SERVICE_MYSQL = 3306, \
    SERVICE_PGSQL = 5432, \
    SERVICE_CACHEDB = 1972
  };

  ServiceDef() {}
  ~ServiceDef() {}

  //! return 0 when not found. port is Host byte order.
  static int find(uint16_t port);
  static const char *service2name(int port);
  static const int name2service(const char *name);

  static const char *protocol2name(int protocol);
  static const int name2protocol(const char *name);

  //! Create some maps.
  //static int create_map();

  //! dump static maps.
  static void dump(std::ostream &os);

protected:
  //! service names.
  //static const value_string service_names_[];

  //! protocol names.
  static const value_string protocol_names_[];

  //! Service of port hash map that NBA surpported.
  static const std::pair<int, int> nba_service_pairs_[];
  static const __gnu_cxx::hash_map<int, int> nba_services_;

  //! Service and name map.
  static const std::pair<int, const std::string> service2name_pairs_[];
  static const std::map<int, const std::string> service2name_;

  //! Service and name map.
  static const std::pair<const std::string, int> name2service_pairs_[];
  static const std::map<const std::string, int> name2service_;
};


#endif	//__SERVICE_DEF_H

