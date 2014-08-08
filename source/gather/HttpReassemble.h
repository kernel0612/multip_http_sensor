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
#include<stdint.h>
using namespace std;
//合并出 完整的一次http的请求和对应的响应  为下一步 分析http字段提供必要的条件

enum{responsefrag,requestfrag};
struct fragKey{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint32_t dport;
};
struct httpfrag{
	struct fragKey key;
	char* frag;
	uint32_t fraglen;
	struct httpfrag* next;
	uint32_t type;
};
struct httpdata{
	char* data;
	uint32_t datalen;
};
class HttpReassemble {
public:
	HttpReassemble();
	virtual ~HttpReassemble();
	int process_httpfrag(struct httpfrag* frag,struct httpdata** defrag);      //0 complete  1 not complete   -1 error
private:
	int is_first_response_frag();   // 包含 HTTP/1.1 200 OK 的包
	uint32_t get_response_len();   //从 首个响应包中的content-length中获取
	int is_chunked_reponse();
	int is_response_done();
	int is_request_done();
	char* response_glue();
	char* request_glue();

private:


};

#endif /* HTTPREASSEMBLE_H_ */
