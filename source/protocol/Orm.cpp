#include "Orm.h"
#include "CIDR.h"
#include "ServiceDef.h"
//#include "PQCopy.h"
#ifndef _WIN32
#include <arpa/inet.h>
#endif
#if 0
int ORM::o2r_stream(const ORMStream &s, char *data, int &size)
{
  if (size < (int)sizeof(ORMStream) + 2 + 24 * 4 + 4) {
    return -1;
  }

  volatile int len = 0;
  len += PQCopy::smallint_o(data + len, 24);
  len += PQCopy::bigint(data + len, s.sid);
  len += PQCopy::timestamp(data + len, s.ts);
  len += PQCopy::integer(data + len, s.duration);
  len += PQCopy::inet(data + len, s.sip);
  len += PQCopy::inet(data + len, s.dip);
  len += PQCopy::smallint(data + len, s.sport);
  len += PQCopy::smallint(data + len, s.dport);
  len += PQCopy::integer(data + len, s.protocol);
  len += PQCopy::integer(data + len, s.service);
  len += PQCopy::integer(data + len, s.eventtype);
  len += PQCopy::integer(data + len, s.bytes);
  len += PQCopy::integer(data + len, s.records);
  len += PQCopy::integer(data + len, s.data_len);
  len += PQCopy::vchar(data + len, (char *)s.data, s.data_len);
  size = len;
  return 0;
}

int ORM::o2r_transaction(const ORMTransaction &t, char *data, int &size)
{
  if (size < (int)sizeof(ORMTransaction) + 2 + 5 * 4 + 4) {
    return -1;
  }

  volatile int len = 0;
  len += PQCopy::smallint_o(data + len, 8);
  len += PQCopy::bigint(data + len, t.sid);
  len += PQCopy::smallint(data + len, t.direct);
  len += PQCopy::timestamp(data + len, t.ts);
  char tmp[8] = {0};
  int tmplen = 0;
  len += PQCopy::vchar(data + len, tmp, tmplen);
  len += PQCopy::vchar(data + len, tmp, tmplen);
  len += PQCopy::vchar(data + len, tmp, tmplen);
  len += PQCopy::vchar(data + len, (char *)t.data, t.data_len);
  size = len;
  return 0;
}
#endif
std::ostream &operator << (std::ostream &os, const ORMEntity &entity)
{
  switch (entity.type) {
  case ORMEntity::STREAM:
    os << "ORM STREAM, " << entity.un.stream;
    break;

  case ORMEntity::TRANSACTION:
    os << "ORM TRANSACTION, " << entity.un.trans;
    break;

  default:
    os << "ORM UNKNOWN, " << entity.len;
    break;
  }

  return os << std::endl;
}

std::ostream &operator << (std::ostream &os, const ORMStream &strm)
{
  os << (strm.eventtype == 0 ? "B " : (strm.eventtype == 1 ? "E " : "U "));
  os << strm.sid << '/' << strm.service << '/' << strm.account << '\t';
  os << CIDR::ntos(strm.sip) << ':' << ntohs(strm.sport) << "->";
  os << CIDR::ntos(strm.dip) << ':' << ntohs(strm.dport) << " ";
  const char *servicename = ServiceDef::service2name(strm.service);

  if (servicename != NULL) {
    os << servicename << ' ';
  } else {
    os << strm.service << ' ';
  }

  os << strm.ts.tv_sec;

  if (strm.eventtype != 0) {
    os << "\t" << strm.duration << '/' << strm.bytes << '/' << strm.records << '\t';
    os << strm.client << '>' << strm.server << '\t' << strm.data_len << ':';
    os.write(strm.data, strm.data_len);
  }

  return os;
}

std::ostream &operator << (std::ostream &os, const ORMTransaction &trans)
{
  os << trans.sid << '/' << trans.seq << ' ' << (trans.direct == 0 ? ">" : "<")  << ")\t";

  if (trans.direct == 0) {
    os << trans.operate << ' ' << trans.object << ' ' << trans.result << ' ';
  }

  os << trans.data_len << " on " << ctime(&trans.ts.tv_sec);
  os.write(trans.data, trans.data_len);
  return os;
}


