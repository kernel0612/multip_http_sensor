#include "Dissector.h"
#include "Stream.h"
#include "Frame.h"
#include "ServiceDef.h"
//#include "DissectorTelnet.h"
//#include "DissectorOracle.h"
//#include "DissectorDB2.h"
//#include "DissectorSybase.h"
//#include "DissectorSQLServer.h"
//#include "DissectorInformix.h"
//#include "DissectorTeradata.h"
//#include "DissectorRsh.h"
//#include "DissectorSMTP.h"
//#include "DissectorPOP3.h"
#include "DissectorHTTP.h"
//#include "DissectorDomino.h"
//#include "DissectorMYSQL.h"
//#include "DissectorPGSQL.h"
//#include "DissectorFTP.h"
//#include "DissectorCachedb.h"
#include <ace/Log_Msg.h>


PortChanged Dissector::port_changed_;

Dissector::Dissector()
{
  memset(trans_, 0, sizeof(trans_));
  //trans_num_ = sizeof(trans_) / sizeof(ORM_Transaction);
  trans_num_ = 0;
}

int Dissector::create()
{
  return 0;
}

int Dissector::destroy()
{
  return 0;
}

int Dissector::dissect(Stream &stream, const Frame &frame)
{
  if (stream.service < ServiceDef::SERVICE_OTHER) {
    return -1;
  }

  int ret = 0;

  // Base service param to determinate transaction level and should be output or not.
  // Split transactiont to operation, object and result. And map to service command level.

  switch (stream.service) {
  case ServiceDef::SERVICE_ORACLE:
   // ret = DissectorOracle::dissect(stream, frame, port_changed_);
    break;

  case ServiceDef::SERVICE_TELNET:
  case ServiceDef::SERVICE_RLOGIN:
  //  ret = DissectorTelnet::dissect(stream, frame);
    break;

  case ServiceDef::SERVICE_FTP:
   // ret = DissectorFTP::dissect(stream, frame, trans_,
                               // trans_num_ = sizeof(trans_) / sizeof(ORMTransaction));
    break;

    //  case ServiceDef::SERVICE_DB2:
    //    ret = DissectorDB2::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_SYBASE:
    //    ret = DissectorSybase::dissect(stream, frame);
    //    break;

  case ServiceDef::SERVICE_SQL:
   // ret = DissectorSQLServer::dissect(stream, frame);
    break;

    //  case ServiceDef::SERVICE_INFORMIX:
    //    ret = DissectorInformix::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_TERADATA:
    //    ret = DissectorTeradata::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_RSH:
    //    ret = DissectorRsh::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_REXEC:
    //    ret = DissectorRsh::dissect_rexec(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_SMTP:
    //    ret = DissectorSMTP::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_POP3:
    //    ret = DissectorPOP3::dissect(stream, frame);
    //    break;

  case ServiceDef::SERVICE_HTTP:
    ret = DissectorHTTP::dissect(stream, frame);
    break;

    //  case ServiceDef::SERVICE_DOMINO:
    //    ret = DissectorDomino::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_MYSQL:
    //    ret = DissectorMYSQL::dissect(stream, frame);
    //    break;
    //
    //  case ServiceDef::SERVICE_PGSQL:
    //    ret = DissectorPGSQL::dissect(stream, frame);
    //    break;
  case ServiceDef::SERVICE_CACHEDB:
   // ret = DissectorCachedb::dissect(stream, frame);
    break;

  default:
    ret = -1;
    break;
  }

  memcpy(&stream.trans.ts, &frame.ts, sizeof(struct timeval));
  return ret;
}

