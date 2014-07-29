#include "XML.h"
#include <cstring>
#include <libxml/xpath.h>

char XML::static_err_[128] = {0};
char XML::value_[256] = {0};

XML::XML() : doc_(NULL)
{
  memset(err_, 0, sizeof(err_));
}

int XML::create(const char *xmlfile)
{
  if (doc_ != NULL) {
    destroy();
  }

  doc_ = xmlParseFile(xmlfile);

  if (doc_ == NULL) {
    snprintf(err_, sizeof(err_) - 1, "Open xml file failed: %s", xmlfile);
    return -1;
  }

  return 0;
}

int XML::destroy()
{
  if (doc_ != NULL) {
    xmlFreeDoc(doc_);
    xmlCleanupParser();
    doc_ = NULL;
  }

  return 0;
}

const char *XML::xpath(const char *path, char *value, int len)
{
  xmlXPathContextPtr context = xmlXPathNewContext(doc_);
  xmlXPathObjectPtr result = xmlXPathEvalExpression((xmlChar *)path, context);

  if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
    snprintf(err_, sizeof(err_) - 1, "not found path: %s", path);
    return NULL;
  }

  xmlChar *xmlvalue = NULL;
  xmlNodeSetPtr nodeset = result->nodesetval;

  for (int i = 0; i < nodeset->nodeNr; i++) {
    xmlvalue = xmlNodeListGetString(doc_, nodeset->nodeTab[i]->xmlChildrenNode, 1);

    if (xmlvalue) {
      strncpy(value, (char *)xmlvalue, len);
    }

    xmlFree(xmlvalue);
    break;
  }

  xmlXPathFreeObject(result);
  return value;
}

int XML::xpath(const char *path, std::vector<std::string> &values)
{
  values.clear();
  xmlXPathContextPtr context = xmlXPathNewContext(doc_);
  xmlXPathObjectPtr result = xmlXPathEvalExpression((xmlChar *)path, context);

  if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
    snprintf(err_, sizeof(err_) - 1, "not found path: %s", path);
    return -1;
  }

  xmlChar *xmlvalue = NULL;
  xmlNodeSetPtr nodeset = result->nodesetval;

  for (int i = 0; i < nodeset->nodeNr; i++) {
    xmlvalue = xmlNodeListGetString(doc_, nodeset->nodeTab[i]->xmlChildrenNode, 1);

    if (xmlvalue) {
      values.push_back((char *)xmlvalue);
    }

    xmlFree(xmlvalue);
  }

  xmlXPathFreeObject(result);
  return 0;
}

// static functions.
const char *XML::xpath(const char *xmlfile, const char *path, char *value, int len)
{
  value[0] = value[len - 1] = '\0';
  xmlDocPtr doc = xmlParseFile(xmlfile);

  if (doc == NULL) {
    snprintf(static_err_, sizeof(static_err_) - 1, "Open xml file failed: %s", xmlfile);
    return NULL;
  }

  xmlXPathContextPtr context = xmlXPathNewContext(doc);
  xmlXPathObjectPtr result = xmlXPathEvalExpression((xmlChar *)path, context);

  if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
    snprintf(static_err_, sizeof(static_err_) - 1, "not found path: %s", path);
    return NULL;
  }

  xmlChar *xmlvalue = NULL;
  xmlNodeSetPtr nodeset = result->nodesetval;

  for (int i = 0; i < nodeset->nodeNr; i++) {
    xmlvalue = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);

    if (xmlvalue) {
      strncpy(value, (char *)xmlvalue, len);
    }

    xmlFree(xmlvalue);
    break;
  }

  xmlXPathFreeObject(result);
  xmlFreeDoc(doc);
  xmlCleanupParser();
  return value;
}

