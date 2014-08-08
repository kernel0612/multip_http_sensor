/*
 * HttpReassemble.h
 *
 *  Created on: 2014��8��8��
 *      Author: Administrator
 */

#ifndef HTTPREASSEMBLE_H_
#define HTTPREASSEMBLE_H_
#include<iostream>
#include<string>
#include<vector>
#include<stdint.h>
using namespace std;
//�ϲ��� ������һ��http������Ͷ�Ӧ����Ӧ  Ϊ��һ�� ����http�ֶ��ṩ��Ҫ������

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
	int is_first_response_frag();   // ���� HTTP/1.1 200 OK �İ�
	uint32_t get_response_len();   //�� �׸���Ӧ���е�content-length�л�ȡ
	int is_chunked_reponse();
	int is_response_done();
	int is_request_done();
	char* response_glue();
	char* request_glue();

private:


};

#endif /* HTTPREASSEMBLE_H_ */
