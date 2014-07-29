#ifndef __XML_H
#define __XML_H

#include <vector>
#include <string>
#include <libxml/parser.h>

/*!
 * @brief This class decleares XML utils based on libxml2.
 */
class XML
{
public:
  XML();
  ~XML() {
    destroy();
  }

  int create(const char *xmlfile);
  int destroy();
  const char *xpath(const char *path, char *value, int len);
  int xpath(const char *path, std::vector<std::string> &values);

  const char *error() {
    return err_;
  }

  // static function.
  static const char *xpath(const char *xmlfile, const char *path) {
    return xpath(xmlfile, path, value_, sizeof(value_));
  }
  static const char *xpath(const char *xmlfile, const char *path, char *value, int len);
  static const char *static_error() {
    return static_err_;
  }

protected:
  char err_[128];
  xmlDocPtr doc_;

  static char static_err_[128];
  static char value_[256];
};


#endif //__XML_H

