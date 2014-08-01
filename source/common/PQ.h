#ifndef __PQ_H
#define __PQ_H

#include <iostream>
#include <cstring>
#include <postgresql/libpq-fe.h>
#include <stdint.h>

/*!
 * @brief The class defines Postgresql C wraps.
 */
class PQ
{
public:
  enum { DISCONN = 0, CONNECT };
  struct record {
    int size;
    char data[3072];
  };

  PQ();
  PQ(const char *ip, uint16_t pport, const char *pdbname, const char *puser, const char *ppasswd, int pconnect_timeout = 0) {
    set(ip, pport, pdbname, puser, ppasswd, pconnect_timeout);
  }
  ~PQ() {
    disconnect();
  }

  int connect();
  int reconnect();
  int disconnect();
  int status() const;
  int exec(const char *sql);
  int execQuery(const char *sql, char *out, int outlen);
  int cancel();
  int copy(const char *sql, const char *records, uint32_t size);
  int copy(const char *sql, const struct record *records, uint32_t num);
  int copy_head(const char *sql);
  int copy_data(const char *record, uint32_t size);
  int copy_end();

  void dump(std::ostream &os) const;

  char *hostaddr(char *ip, uint32_t len) const {
    ip[len - 1] = '\0';
    return strncpy(ip, hostaddr_, len - 1);
  }
  void hostaddr(const char *ip) {
    hostaddr_[sizeof(hostaddr_) - 1] = '\0';
    strncpy(hostaddr_, ip, sizeof(hostaddr_) - 1);
  }

  uint16_t port() const {
    return port_;
  }
  void port(uint16_t pport) {
    port_ = pport;
  }

  char *dbname(char *db, uint32_t len) const {
    db[len - 1] = '\0';
    return strncpy(db, dbname_, len - 1);
  }
  void dbname(const char *db) {
    dbname_[sizeof(dbname_) - 1] = '\0';
    strncpy(dbname_, db, sizeof(dbname_) - 1);
  }

  char *user(char *puser, uint32_t len) const {
    puser[len - 1] = '\0';
    return strncpy(puser, user_, len - 1);
  }
  void user(const char *puser) {
    user_[sizeof(user_) - 1] = '\0';
    strncpy(user_, puser, sizeof(user_) - 1);
  }

  char *passwd(char *pass, uint32_t len) const {
    pass[len - 1] = '\0';
    return strncpy(pass, passwd_, len - 1);
  }
  void passwd(const char *pass) {
    passwd_[sizeof(passwd_) - 1] = '\0';
    strncpy(passwd_, pass, sizeof(passwd_) - 1);
  }

  int connect_timeout() const {
    return connect_timeout_;
  }
  void connect_timeout(int timeout) {
    connect_timeout_ = timeout;
  }

  void set(const char *ip, uint16_t pport, const char *pdbname, const char *puser, const char *ppasswd, int pconnect_timeout = 0) {
    hostaddr(ip);
    port(pport);
    dbname(pdbname);
    user(puser);
    passwd(ppasswd);
    connect_timeout(pconnect_timeout);
  }

  void format(const char *source, char *dest, size_t length);
protected:
  char hostaddr_[16];
  uint16_t port_;
  char dbname_[32];
  char user_[32];
  char passwd_[32];
  int connect_timeout_;

  PGconn *conn_;
};

#endif	//__PQ_H

