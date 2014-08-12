/*
 * HttpReassemble.h
 *
 *  Created on: 2014年8月8日
 *      Author: Administrator
 */

#ifndef HTTPREASSEMBLE_H_
#define HTTPREASSEMBLE_H_
#include<iostream>
#include<string>
#include<vector>
#include<map>
#include<set>
#include<stdint.h>
using namespace std;
//合并出 完整的一次http的请求和对应的响应  为下一步 分析http字段提供必要的条件

enum{responsefrag,requestfrag};
enum{interaction_begin,interaction_update,interaction_close,interaction_rst,interaction_timeout};
struct fragKey{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint32_t dport;

	  bool operator < (const fragKey &k2) const {
	    return memcmp(this, &k2, sizeof(fragKey)) < 0;
	  }

	  bool operator == (const fragKey &k2) const {
	    return (sip == k2.sip && dip == k2.dip && sport == k2.sport && \
	            dport == k2.dport) || (dip == k2.sip && sip == k2.dip && \
	                                   dport == k2.sport && sport == k2.dport);
	  }
};
struct httpfrag{
	struct fragKey key;
	char* frag;
	uint32_t fraglen;
	uint32_t type;
};
struct http_interaction{              //一次请求和响应
	uint32_t status;
	vector<struct httpfrag*> request;
	vector<struct httpfrag*> response;
};
struct http_session{                 //一次会话
	char sessionid[64];
	uint32_t start;
	uint32_t end;
	vector<struct http_interaction> interactons;
};
struct httpdata{
	char* data;
	uint32_t datalen;
};
class HttpReassemble {
public:
	HttpReassemble();
	virtual ~HttpReassemble();
	int load_config();  //加载过滤
	int process_httpfrag(struct httpfrag* frag,struct http_interaction** defrag);      //0 complete  1 not complete   -1 error  2 need drop
	int process_interaction_status(struct fragKey& key,uint32_t status);
private:
	int is_first_response_frag(struct httpfrag* frag);   // 包含 HTTP/1.1 200 OK 的包  ret 1  or return 0 -1 error
	int is_first_request_frag(struct httpfrag* frag);    //包含 GET HEAD POST 的包  ret 1  or return 0 -1 error
	int get_response_len(struct httpfrag* frag);   //从 首个响应包中的content-length中获取
	int is_chunked_reponse(struct httpfrag* frag);
	int is_response_done();
	int is_request_done();
	char* response_glue();
	char* request_glue();
	int get_header_field(const char* source,string& field,const char* fieldName);
	int if_finded_erase_it(struct fragKey& key);
	int is_frag_need_drop(struct httpfrag* frag);  //请求被丢弃 则 响应也不捕获

private:
    std::map<struct fragKey,struct http_interaction > _interation_table;
   // std::map<struct fragKey,timer> _interacion_timer;

    set<struct fragKey> _drop_requests;

};

#endif /* HTTPREASSEMBLE_H_ */
