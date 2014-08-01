#include "PQ.h"
//#include <ace/Log_Msg.h>

PQ::PQ() : port_(0), connect_timeout_(0), conn_(NULL)
{
  memset(this->hostaddr_, 0, sizeof(this->hostaddr_));
  memset(this->dbname_, 0, sizeof(this->dbname_));
  memset(this->user_, 0, sizeof(this->user_));
  memset(this->passwd_, 0, sizeof(this->passwd_));
}

int PQ::connect()
{
  char s[512] = {0};
  snprintf(s, sizeof(s) - 1, "hostaddr='%s' port='%d' dbname='%s' user='%s' password='%s' connect_timeout=%d", \
           this->hostaddr_, this->port_, this->dbname_, this->user_, this->passwd_, this->connect_timeout_);

  if ((this->conn_ = PQconnectdb(s)) == NULL) {
	  fprintf(stderr,"%s",PQerrorMessage(conn_));
    return -1;
  }

  if (PQstatus(this->conn_) != CONNECTION_OK) {
	  fprintf(stderr,"%s",PQerrorMessage(conn_));
    PQfinish(this->conn_);
    this->conn_ = NULL;
    return -1;
  }

  return 0;
}

int PQ::reconnect()
{
  if (this->conn_ != NULL) {
    PQreset(this->conn_);

    if (PQstatus(this->conn_) != CONNECTION_OK) {
      PQfinish(this->conn_);
      this->conn_ = NULL;
      return -1;
    }
  } else {
    return connect();
  }

  return 0;
}

int PQ::disconnect()
{
  if (this->conn_ != NULL) {
    PQfinish(this->conn_);
    this->conn_ = NULL;
  }

  return 0;
}

/*
 * 0 means OK, -1 means BAD.
 */
int PQ::status() const
{
  if (PQstatus(this->conn_) != CONNECTION_OK) {
    return -1;
  }

  return 0;
}

/*
 * Return 0 means sucessful. -1 means failed. -2 means fatal error, need reconnect.
 */
int PQ::exec(const char *sql)
{
  PGresult *res = NULL;

  if ((res = PQexec(this->conn_, sql)) == NULL) {
    if (PQstatus(this->conn_) == CONNECTION_OK) {
		fprintf(stderr,"%s",PQerrorMessage(conn_));
      return -1;
    } else {
		fprintf(stderr,"%s",PQerrorMessage(conn_));
      return -2;
    }
  }

  int ret = 0;

  switch (PQresultStatus(res)) {
  case PGRES_BAD_RESPONSE :
    ret = -1;
    break;

  case PGRES_FATAL_ERROR:
  case PGRES_NONFATAL_ERROR:
    if (PQstatus(this->conn_) == CONNECTION_OK) {
      ret = -1;
    } else {
      ret = -2;
    }

    break;

  case PGRES_COMMAND_OK:
  case PGRES_EMPTY_QUERY:
  case PGRES_TUPLES_OK :
  case PGRES_COPY_OUT :
  case PGRES_COPY_IN:
    ret = 0;
    break;

  default:
    break;
  }

  PQclear(res);
  return ret;
}

int PQ::execQuery(const char *sql, char *out, int outlen)
{
  PGresult *res = NULL;

  if ((res = PQexec(this->conn_, sql)) == NULL) {
    if (PQstatus(this->conn_) == CONNECTION_OK) {
		fprintf(stderr,"%s",PQerrorMessage(conn_));
      return -1;
    } else {
      return -2;
    }
  }

  int ret = 0;

  switch (PQresultStatus(res)) {
  case PGRES_BAD_RESPONSE :
    ret = -1;
    break;

  case PGRES_FATAL_ERROR:
  case PGRES_NONFATAL_ERROR:
    if (PQstatus(this->conn_) == CONNECTION_OK) {
      ret = -1;
    } else {
      ret = -2;
    }

    break;

  case PGRES_COMMAND_OK:
  case PGRES_EMPTY_QUERY:
  case PGRES_COPY_OUT :
  case PGRES_COPY_IN:
    ret = -1;
    break;

  case PGRES_TUPLES_OK :
    out[0] = '\0';

    for (int i = 0; i < PQntuples(res); i++) {
      for (int j = 0; j < PQnfields(res); j++) {
        strncpy(out, PQgetvalue(res, i, j), outlen);
        strncpy(out, "|", outlen);
      }

      //strncpy(out, "\n", outlen);
    }

    ret = 0;
    break;

  default:
    break;
  }

  PQclear(res);
  return ret;
}

int PQ::cancel()
{
  /*PGcancel* canc = PQgetCancel(this->conn_);
  if (canc == NULL)
  	return -1;
  char err[256];
  if (PQcancel(canc, err, sizeof(err)) == 0)
  	return -1;
  PQfreeCancel(canc);*/
  return 0;
}

int PQ::copy(const char *sql, const char *records, uint32_t size)
{
  PGresult *res = NULL;
  res = PQexec(this->conn_, sql);

  if (PQresultStatus(res) != PGRES_COPY_IN) {
	  fprintf(stderr,"%s",PQerrorMessage(conn_));
    PQclear(res);
    return -1;
  }

  PQclear(res);

  if (PQputCopyData(this->conn_, (char *)records, size) < 0) {
	  fprintf(stderr,"%s",PQerrorMessage(conn_));
    return -3;
  }

  char *err = NULL;

  if (PQputCopyEnd(this->conn_, err) < 0) {
	  fprintf(stderr,"%s",PQerrorMessage(conn_));
    return -5;
  }

  res = PQgetResult(this->conn_);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	  fprintf(stderr,"%s",PQerrorMessage(conn_));
    PQclear(res);
    return -6;
  }

  PQclear(res);
  return 0;
}

int PQ::copy(const char *sql, const struct record *records, uint32_t num)
{
  PGresult *res = NULL;
  res = PQexec(this->conn_, sql);

  if (PQresultStatus(res) != PGRES_COPY_IN) {
    PQclear(res);
    return -1;
  }

  PQclear(res);

  for (uint32_t i = 0; i < num; i++)
    if (PQputCopyData(this->conn_, records[i].data, records[i].size) < 0) {
      //ACE_DEBUG((LM_ERROR, "PQ: PQputCopyData[%s]", records[i].data));
      return -3;
    } else {
      //ACE_DEBUG((LM_DEBUG, "PQ: PQputCopyData[%s]", records[i].data));
    }

  char *err = NULL;

  if (PQputCopyEnd(this->conn_, err) < 0) {
    return -5;
  }

  res = PQgetResult(this->conn_);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -6;
  }

  PQclear(res);
  return 0;
}

int PQ::copy_head(const char *sql)
{
  PGresult *res = NULL;
  res = PQexec(this->conn_, sql);

  if (PQresultStatus(res) != PGRES_COPY_IN) {
    PQclear(res);
    return -1;
  }

  PQclear(res);
  return 0;
}

int PQ::copy_data(const char *record, uint32_t size)
{
  if (PQputCopyData(this->conn_, record, size) < 0) {
    return -1;
  }

  return 0;
}

int PQ::copy_end()
{
  char *err = NULL;

  if (PQputCopyEnd(this->conn_, err) < 0) {
    return -1;
  }

  PGresult *res = NULL;
  res = PQgetResult(this->conn_);

  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    PQclear(res);
    return -2;
  }

  PQclear(res);
  return 0;
}


void PQ::dump(std::ostream &os) const
{
  os << "Status: " << (PQstatus(this->conn_) == CONNECTION_OK ? "Connected" : "Disconnected") << "\t";
  os << "hostaddr=" << this->hostaddr_ << ' ' \
     << "port=" << this->port_ << ' ' \
     << "dbname=" << this->dbname_ << ' ' \
     << "user=" << this->user_ << ' ' \
     << "password=" << this->passwd_ << ' ' \
     << "connect_timeout=" << this->connect_timeout_;
}

void PQ::format(const char *source, char *dest, size_t length)
{
  int err;
  PQescapeStringConn(this->conn_, dest, source, length, &err);
}

