#ifndef __GATHER_POLICY_H
#define __GATHER_POLICY_H

#include <vector>
#include <iostream>
#include "Stream.h"
#include <ace/RW_Thread_Mutex.h>

class ClientRules
{
public:
  enum {DROP = 0, GATHER = 1};
  uint32_t sip;
  uint32_t smask;
  int audit;
};

class SevicesRules
{
public:
  uint32_t dip;
  uint32_t dmask;
  uint16_t dport;
  int services;
  std::vector<ClientRules> rejectList;
};

/*!
 */
class GatherPolicy
{
public:
  GatherPolicy();
  ~GatherPolicy() {}

  int create();
  int destroy();
  int reload(void);

  // return whether audit. return values is -1 means failed. Otherwise will return DROP or GATHER;
  int find_policy(const StreamKey &key, int &service) const;
  int find_policy(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int &service) const;
  int match_rule(const StreamKey &key, std::ostream &os, bool verbose) const;

  const char *rule_file() const {
    return rule_file_;
  }

  void rule_file(const char *file) {
    strncpy(rule_file_, file, sizeof(rule_file_));
  }

  const std::vector<ClientRules> &clientRules() const {
    return clientList;
  }

  const std::vector<SevicesRules> &serviceRules() const {
    return serviceList;
  }

  void dump(std::ostream &os) const;
  const char *error() const {
    return err_;
  }

protected:
  int load_xml();

protected:
  char rule_file_[256];
  char err_[128];

  std::vector<ClientRules> clientList;
  std::vector<SevicesRules> serviceList;
  mutable ACE_RW_Thread_Mutex mutex_;
};

std::ostream &operator << (std::ostream &os, const ClientRules &rule);
std::ostream &operator << (std::ostream &os, const SevicesRules &rule);

#endif
