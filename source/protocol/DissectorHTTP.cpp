#include "DissectorHTTP.h"
#include "Stream.h"
#include "Frame.h"

// return 0 means no transaction, 1: means transaction, 2: means response.
// 3 means both transaciton and response. -1 means failed.
int DissectorHTTP::dissect(Stream &stream, const Frame &frame)
{
  const char *payload = NULL;
  int len = frame.payload(&payload);

  if (len <= 0) {
    return 0;
  }

  char tmp[4] = {0};
  tmp[0] = toupper(payload[0]);
  tmp[1] = toupper(payload[1]);
  tmp[2] = toupper(payload[2]);
  tmp[3] = toupper(payload[3]);
  const struct iphdr *iph = frame.iphdr();

  if (iph->saddr == stream.key.saddr) {	// UP
    if (memcmp(tmp, "GET", 3) == 0) {
      for (int i = 0; i < len; i++) {
        if (payload[i] == '\r' || payload[i] == '\n') {
          len = i;
          break;
        }
      }
    } else if (memcmp(tmp, "POST", 4) == 0) {
      int i = 0, j = 0, pos = 0;

      for (; i < len; i++) {
        if (payload[i] == '\n') {
          if (j == 0) {
            pos = i;
          }

          if ((i - j == 1) || (i - j == 2 && payload[j + 1] == '\r')) {
            break;
          }

          j = i;
        }
      }

      if (++i < len) {
        char tmp[1024] = {0};
        //int len = (int)sizeof(tmp) < len - i ? sizeof(tmp) : len - i;
        int bodylen = std::min((int)sizeof(tmp), len - i);
        memcpy(tmp, payload + i, bodylen);
        memcpy((char *)payload + pos + 1, tmp, bodylen);
        len -= i;
        //len += pos + 1;
      } else {
        len = pos;
      }
    } else {
      return 0;
    }

    stream.trans.data_len = len;
    strncpy(stream.trans.data, payload, len + 1);
    return 1;
  } else {
    if (memcmp(tmp, "HTTP", 4) == 0) {
      char *p = NULL;

      //if (strstr((char*)payload, "OK") == NULL) return returnno;
      if ((p = strstr((char *)payload, "Content-Type: ")) == NULL) {
        return 0;
      }

      int tmplen = p - payload + 14 + 9 + 2;

      if (tmplen <= 0 || tmplen > len) {
        return 0;
      }

      if (memcmp(p + 14, "text/html", 9) != 0) {
        return 0;
      }

      int i = 14 + 9 + 2, j = 14 + 9 + 2;

      for (; i < len; i++) {
        if (payload[i] == '\n') {
          if ((i - j == 1) || (i - j == 2 && payload[j + 1] == '\r')) {
            break;
          }

          j = i;
        }
      }

      if (++i < len) {
        payload = payload + i;
        len -= i;
      } else {
        return 0;
      }
    } else {
      return 0;
    }

    strncpy(stream.response, payload, len);
    return 2;
  }

  return 0;
}

