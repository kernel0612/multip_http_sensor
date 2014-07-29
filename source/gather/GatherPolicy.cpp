#include "GatherPolicy.h"
#include "CIDR.h"
#include "Stream.h"
#include "XML.h"
#include "ServiceDef.h"
#include <arpa/inet.h>
#include <ace/Log_Msg.h>

std::ostream &operator << (std::ostream &os, const ClientRules &rule)
{
  char tmp[32] = {0};
  CIDR::addr2cidr(rule.sip, rule.smask, tmp, sizeof(tmp));
  os << "ip:" << tmp << ':' ;

  if (rule.audit == ClientRules::DROP) {
    os << "DROP" << std::endl;
  } else {
    os << "GATHER" << std::endl;
  }

  return os;
}

GatherPolicy::GatherPolicy()
{
  memset(rule_file_, 0, sizeof(rule_file_));
  memset(err_, 0, sizeof(err_));
}

/*
 * Craete host tree and all user tree.
 */
int GatherPolicy::create()
{
  if (strlen(rule_file_) == 0) {
    strncpy(err_, "rule file name is empty.", sizeof(err_));
    return -1;
  }

  mutex_.acquire_write();
  clientList.reserve(2048);	// Reserve 2048 rules.
  serviceList.reserve(2048);
  int ret = load_xml();
  mutex_.release();
  return ret;
}

int GatherPolicy::destroy()
{
  mutex_.acquire_write();
  clientList.clear();
  serviceList.clear();
  mutex_.release();
  return 0;
}

int GatherPolicy::reload()
{
  destroy();
  return create();
}

int GatherPolicy::find_policy(const StreamKey &key, int &service) const
{
  return find_policy(key.saddr, key.daddr, key.sport, key.dport, service);
}

/*
   指定IP和端口的服务是否允许
*/
int GatherPolicy::find_policy(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int &service) const
{
  mutex_.acquire_read();
  std::vector<SevicesRules>::const_iterator hit = serviceList.begin();

  for (; hit != serviceList.end(); ++hit) {
    if ((hit->dip == (dip & hit->dmask) && (hit->dport == 0 || hit->dport == dport))
        || hit->dip == (sip & hit->dmask) && (hit->dport == 0 || hit->dport == sport)) {
      std::vector<ClientRules>::const_iterator iit = hit->rejectList.begin();
      service = hit->services;

      for (; iit != hit->rejectList.end(); ++iit) {
        if (iit->sip == (sip & iit->smask)) {
          mutex_.release();
          return iit->audit;
        }
      }

      std::vector<ClientRules>::const_iterator iiit = clientList.begin();

      for (; iiit != hit->rejectList.end(); ++iiit) {
        if (iiit->sip == (sip & iiit->smask)) {
          mutex_.release();
          return iiit->audit;
        }
      }

      // if not found user or trust.
      mutex_.release();
      return ClientRules::GATHER;
    }
  }

  mutex_.release();
  return ClientRules::DROP;
}

void GatherPolicy::dump(std::ostream &os) const
{
  os << "\trule_file=" << rule_file_ << std::endl;
  os << "\t[CLIENT]\n";
  mutex_.acquire_read();
  std::vector<ClientRules>::const_iterator it = clientList.begin();

  for (; it != clientList.end(); ++it) {
    os << "\tip=" << CIDR::ntos(it->sip) << "\tmask=" << CIDR::ntos(it->smask);

    if (it->audit == ClientRules::DROP) {
      os << "\tDROP" << std::endl;
    } else {
      os << "\tGATHER" << std::endl;
    }
  }

  char tmp[32] = {0};
  os << "\n\t[HOST_NODE]\n";
  std::vector<SevicesRules>::const_iterator hit = serviceList.begin();

  for (; hit != serviceList.end(); ++hit) {
    CIDR::addr2cidr(hit->dip, hit->dmask, tmp, sizeof(tmp));
    os << "\t" << tmp;
    os << "\t: " << ntohs(hit->dport) << '/' << ServiceDef::service2name(hit->services);
    os << std::endl;
    std::vector<ClientRules>::const_iterator iit = hit->rejectList.begin();

    for (; iit != hit->rejectList.end(); ++iit) {
      CIDR::addr2cidr(iit->sip, iit->smask, tmp, sizeof(tmp));
      os << "\t" << tmp << '\t';

      if (iit->audit == ClientRules::DROP) {
        os << "DROP";
      } else {
        os << "GATHER";
      }

      os << std::endl;
    }
  }

  mutex_.release();
}

int GatherPolicy::load_xml(void)
{
  XML xml;

  if (xml.create(rule_file_) < 0) {
    strncpy(err_, xml.error(), sizeof(err_));
    return -1;
  }

  char path[128] = {0};
  std::vector<std::string> values;

  //ClientRules
  if (xml.xpath("/gather/network/sipaddr/@ip", values) == 0) {
    std::vector<std::string>::const_iterator addr = values.begin();

    for (; addr != values.end(); addr++) {
      snprintf(path, 128 - 1, "/gather/network/sipaddr[@ip='%s']", addr->c_str());
      std::vector<std::string> audit;

      if (xml.xpath(path, audit) == 0) {
        std::vector<std::string>::const_iterator a = audit.begin();
        ClientRules rules;
        CIDR::cidr2addr(addr->c_str(), rules.sip, rules.smask);

        for (; a != audit.end(); a++) {
          if (strcasecmp(a->c_str(), "yes") == 0) {
            rules.audit = ClientRules::GATHER;
          } else {
            rules.audit = ClientRules::DROP;
          }
        }

        clientList.push_back(rules);
      } else {
        ACE_DEBUG((LM_ERROR, " %s is null", path));
      }
    }
  } else {
    ACE_DEBUG((LM_ERROR, " /gather/network/sipaddr/@ip is null \n"));
  }

  //SevicesRules
  values.clear();

  if (xml.xpath("/gather/services/service/@id", values) == 0) {
    std::vector<std::string>::const_iterator sid = values.begin();
    int id = 0;
    SevicesRules sevicesRules;

    for (; sid != values.end(); sid++) {
      id = atoi(sid->c_str());
      int services;
      int port;
      memset(path, 0, 128);
      snprintf(path, 128 - 1, "/gather/services/service[@id='%d']/@name", id);
      std::vector<std::string> namelist;

      if (xml.xpath(path, namelist) == 0) {
        std::vector<std::string>::const_iterator name = namelist.begin();

        for (; name != namelist.end(); name++) {
          if ((services = ServiceDef::name2service(name->c_str())) < ServiceDef::SERVICE_OTHER) {
            services = ServiceDef::SERVICE_OTHER;
          }
        }
      } else {
        ACE_DEBUG((LM_ERROR, " %s is null\n", path));
      }

      memset(path, 0, 128);
      snprintf(path, 128 - 1, "/gather/services/service[@id='%d']/@port", id);
      std::vector<std::string> portList;

      if (xml.xpath(path, portList) == 0) {
        std::vector<std::string>::const_iterator p = portList.begin();

        for (; p != portList.end(); p++) {
          port = atoi(p->c_str());
        }
      } else {
        ACE_DEBUG((LM_ERROR, " %s is null\n", path));
      }

      memset(path, 0, 128);
      snprintf(path, 128 - 1, "/gather/services/service[@id='%d']/sipaddr/@ip", id);
      std::vector<std::string> sipaddrlist;
      std::vector<ClientRules> clientRulesList;

      if (xml.xpath(path, sipaddrlist) == 0) {
        std::vector<std::string>::const_iterator sipaddr = sipaddrlist.begin();

        for (; sipaddr != sipaddrlist.end(); sipaddr++) {
          ClientRules client;
          uint32_t sip;
          uint32_t smask;
          CIDR::cidr2addr(sipaddr->c_str(), sip, smask);
          client.sip = sip;
          client.smask = smask;
          client.audit = ClientRules::DROP;
          clientRulesList.push_back(client);
        }
      } else {
        ACE_DEBUG((LM_ERROR, " %s is null\n", path));
      }

      memset(path, 0, 128);
      snprintf(path, 128 - 1, "/gather/services/service[@id='%d']/dipaddr/@ip", id);
      std::vector<std::string> dipaddrlist;

      if (xml.xpath(path, dipaddrlist) == 0) {
        std::vector<std::string>::const_iterator dipaddr = dipaddrlist.begin();

        for (; dipaddr != dipaddrlist.end(); dipaddr++) {
          SevicesRules sevices;
          sevices.services = services;
          sevices.dport = htons(port);
          uint32_t sip;
          uint32_t smask;
          CIDR::cidr2addr(dipaddr->c_str(), sip, smask);
          sevices.dip = sip;
          sevices.dmask = smask;
          sevices.rejectList = clientRulesList;
          serviceList.push_back(sevices);
        }
      } else {
        ACE_DEBUG((LM_ERROR, " %s is null\n", path));
      }
    }
  } else {
    ACE_DEBUG((LM_ERROR, "xml file handle is failde, error= %s\n", xml.error()));
  }

  xml.destroy();
  return 0;
}

int GatherPolicy::match_rule(const StreamKey &key, std::ostream &os, bool verbose) const
{
  if (verbose) {
    dump(os);
    os << std::endl;
  }

  os << "TCP stream\t" << CIDR::ntos(key.saddr) << ":" << ntohs(key.sport);
  os << " --> " << CIDR::ntos(key.daddr) << ":" << ntohs(key.dport) << std::endl;
  int ret = 0;
  int service = 0;
  ret = find_policy(key, service);

  if (ret == -1) {
    os << " This TCP stream is not matched any gather policy.\n";
  } else if (ret == ClientRules::GATHER) {
    os << " This TCP stream is " << ServiceDef::service2name(service) << ", should be " << "[ Gather ]" << std::endl;
  } else {
    os << " This TCP stream is " << ServiceDef::service2name(service) << ", should be " << "[ DROP ]" << std::endl;
  }

  return ret;
}

