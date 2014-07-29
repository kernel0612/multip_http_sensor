#include "ServiceDef.h"
#include <strings.h>

//! protocol names.
const ServiceDef::value_string ServiceDef::protocol_names_[] = {
  { 6, "tcp" },
  { 17, "udp" },
  { -1, "unknown" }
};

const std::pair<int, int> ServiceDef::nba_service_pairs_[] = {
  std::make_pair(static_cast<int>(SERVICE_FTP), static_cast<int>(SERVICE_FTP)),
  std::make_pair(static_cast<int>(SERVICE_TELNET), static_cast<int>(SERVICE_TELNET)),
  std::make_pair(static_cast<int>(SERVICE_ORACLE), static_cast<int>(SERVICE_ORACLE)),
  std::make_pair(static_cast<int>(SERVICE_SYBASE), static_cast<int>(SERVICE_SYBASE)),
  std::make_pair(static_cast<int>(SERVICE_DB2), static_cast<int>(SERVICE_DB2)),
  std::make_pair(static_cast<int>(SERVICE_SQL), static_cast<int>(SERVICE_SQL)),
  std::make_pair(static_cast<int>(SERVICE_HTTP), static_cast<int>(SERVICE_HTTP)),
  std::make_pair(static_cast<int>(SERVICE_SMTP), static_cast<int>(SERVICE_SMTP)),
  std::make_pair(static_cast<int>(SERVICE_POP3), static_cast<int>(SERVICE_POP3)),
  std::make_pair(static_cast<int>(SERVICE_X11), static_cast<int>(SERVICE_X11)),
  std::make_pair(static_cast<int>(SERVICE_SSH), static_cast<int>(SERVICE_SSH)),
  std::make_pair(static_cast<int>(SERVICE_REXEC), static_cast<int>(SERVICE_REXEC)),
  std::make_pair(static_cast<int>(SERVICE_RLOGIN), static_cast<int>(SERVICE_RLOGIN)),
  std::make_pair(static_cast<int>(SERVICE_RSH), static_cast<int>(SERVICE_RSH)),
  std::make_pair(static_cast<int>(SERVICE_INFORMIX), static_cast<int>(SERVICE_INFORMIX)),
  std::make_pair(static_cast<int>(SERVICE_TERADATA), static_cast<int>(SERVICE_TERADATA)),
  std::make_pair(static_cast<int>(SERVICE_DOMINO), static_cast<int>(SERVICE_DOMINO)),
  std::make_pair(static_cast<int>(SERVICE_RDP), static_cast<int>(SERVICE_RDP)),
  std::make_pair(static_cast<int>(SERVICE_MYSQL), static_cast<int>(SERVICE_MYSQL)),
  std::make_pair(static_cast<int>(SERVICE_PGSQL), static_cast<int>(SERVICE_PGSQL)),
  std::make_pair(static_cast<int>(SERVICE_CACHEDB), static_cast<int>(SERVICE_CACHEDB))
};

//! Service of port hash map that NMA surpported.
const __gnu_cxx::hash_map<int, int> ServiceDef::nba_services_(
  nba_service_pairs_,
  nba_service_pairs_ + sizeof(nba_service_pairs_)
  / sizeof(nba_service_pairs_[0]));

const std::pair<int, const std::string> ServiceDef::service2name_pairs_[] = {
  std::make_pair(static_cast<int>(SERVICE_OTHER), "other"),
  std::make_pair(static_cast<int>(SERVICE_FTP), "ftp"),
  std::make_pair(static_cast<int>(SERVICE_TELNET), "telnet"),
  std::make_pair(static_cast<int>(SERVICE_ORACLE), "oracle"),
  std::make_pair(static_cast<int>(SERVICE_SYBASE), "sybase"),
  std::make_pair(static_cast<int>(SERVICE_DB2), "db2"),
  std::make_pair(static_cast<int>(SERVICE_SQL), "sqlserver"),
  std::make_pair(static_cast<int>(SERVICE_HTTP), "http"),
  std::make_pair(static_cast<int>(SERVICE_SMTP), "smtp"),
  std::make_pair(static_cast<int>(SERVICE_POP3), "pop3"),
  std::make_pair(static_cast<int>(SERVICE_X11), "x11"),
  std::make_pair(static_cast<int>(SERVICE_SSH), "ssh"),
  std::make_pair(static_cast<int>(SERVICE_REXEC), "rexec"),
  std::make_pair(static_cast<int>(SERVICE_RLOGIN), "rlogin"),
  std::make_pair(static_cast<int>(SERVICE_RSH), "rsh"),
  std::make_pair(static_cast<int>(SERVICE_INFORMIX), "informix"),
  std::make_pair(static_cast<int>(SERVICE_TERADATA), "teradata"),
  std::make_pair(static_cast<int>(SERVICE_DOMINO), "domino"),
  std::make_pair(static_cast<int>(SERVICE_RDP), "rdp"),
  std::make_pair(static_cast<int>(SERVICE_MYSQL), "mysql"),
  std::make_pair(static_cast<int>(SERVICE_PGSQL), "pgsql"),
  std::make_pair(static_cast<int>(SERVICE_CACHEDB), "cachedb")
};

//! Service and name map.
const std::map<int, const std::string> ServiceDef::service2name_(
  service2name_pairs_,
  service2name_pairs_ + sizeof(service2name_pairs_)
  / sizeof(service2name_pairs_[0]));

const std::pair<const std::string, int> ServiceDef::name2service_pairs_[] = {
  std::make_pair("other", static_cast<int>(SERVICE_OTHER)),
  std::make_pair("ftp", static_cast<int>(SERVICE_FTP)),
  std::make_pair("telnet", static_cast<int>(SERVICE_TELNET)),
  std::make_pair("oracle", static_cast<int>(SERVICE_ORACLE)),
  std::make_pair("sybase", static_cast<int>(SERVICE_SYBASE)),
  std::make_pair("db2", static_cast<int>(SERVICE_DB2)),
  std::make_pair("sqlserver", static_cast<int>(SERVICE_SQL)),
  std::make_pair("http", static_cast<int>(SERVICE_HTTP)),
  std::make_pair("smtp", static_cast<int>(SERVICE_SMTP)),
  std::make_pair("pop3", static_cast<int>(SERVICE_POP3)),
  std::make_pair("x11", static_cast<int>(SERVICE_X11)),
  std::make_pair("ssh", static_cast<int>(SERVICE_SSH)),
  std::make_pair("rexec", static_cast<int>(SERVICE_REXEC)),
  std::make_pair("rlogin", static_cast<int>(SERVICE_RLOGIN)),
  std::make_pair("rsh", static_cast<int>(SERVICE_RSH)),
  std::make_pair("informix", static_cast<int>(SERVICE_INFORMIX)),
  std::make_pair("teradata", static_cast<int>(SERVICE_TERADATA)),
  std::make_pair("domino", static_cast<int>(SERVICE_DOMINO)),
  std::make_pair("rdp", static_cast<int>(SERVICE_RDP)),
  std::make_pair("mysql", static_cast<int>(SERVICE_MYSQL)),
  std::make_pair("pgsql", static_cast<int>(SERVICE_PGSQL)),
  std::make_pair("cachedb", static_cast<int>(SERVICE_CACHEDB))
};

//! Service and name map.
const std::map<const std::string, int> ServiceDef::name2service_(
  name2service_pairs_,
  name2service_pairs_ + sizeof(name2service_pairs_)
  / sizeof(name2service_pairs_[0]));

int ServiceDef::find(uint16_t port)
{
  __gnu_cxx::hash_map<int, int>::const_iterator cit = nba_services_.find(port);

  if (cit == nba_services_.end()) {
    return 0;
  }

  return cit->second;
}

const char *ServiceDef::service2name(int port)
{
  std::map<int, const std::string>::const_iterator it =
    service2name_.find(port);

  if (it == service2name_.end()) {
    return service2name_pairs_[1].second.c_str();
  }

  return it->second.c_str();
}

const int ServiceDef::name2service(const char *name)
{
  char tmp[16] =
  { 0 };

  for (uint32_t i = 0; i < sizeof(tmp) - 1 && name[i] != '\0'; i++) {
    tmp[i] = tolower(name[i]);
  }

  std::map<const std::string, int>::const_iterator it = name2service_.find(tmp);

  if (it == name2service_.end()) {
    return -1;
  }

  return it->second;
}

const char *ServiceDef::protocol2name(int protocol)
{
  if (protocol == 6) { // IPPROTO_TCP
    return protocol_names_[0].strptr;
  }

  if (protocol == 17) { // IPPROTO_UDP
    return protocol_names_[1].strptr;
  }

  return protocol_names_[2].strptr;
}

const int ServiceDef::name2protocol(const char *name)
{
  if (strcasecmp(name, "tcp") == 0) {
    return 6; // IPPROTO_TCP
  }

  if (strcasecmp(name, "udp") == 0) {
    return 17; // IPPROTO_UDP
  }

  return -1;
}

//! dump static maps.
void ServiceDef::dump(std::ostream &os)
{
  int size = nba_services_.size();
  os << "[NBA services]\t" << size << std::endl;
  __gnu_cxx ::hash_map<int, int>::const_iterator sit = nba_services_.begin();

  for (int i = 0; sit != nba_services_.end() && i < size; ++sit, ++i) {
    os << i << ":\t" << sit->first << " - " << sit->second << std::endl;
  }

  size = service2name_.size();
  os << "[service2name]\t" << size << std::endl;
  std::map<int, const std::string>::const_iterator cit = service2name_.begin();

  for (int i = 0; cit != service2name_.end() && i < size; ++cit, ++i) {
    os << i << ":\t" << cit->first << " - " << cit->second << std::endl;
  }

  size = name2service_.size();
  os << "[name2service]\t" << size << std::endl;
  std::map<const std::string, int>::const_iterator it = name2service_.begin();

  for (int i = 0; it != name2service_.end() && i < size; ++it, ++i) {
    os << i << ":\t" << it->first << " - " << it->second << std::endl;
  }
}

