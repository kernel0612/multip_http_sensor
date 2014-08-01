/*
 * httpUtil.h
 *
 *  Created on: 2014Äê8ÔÂ1ÈÕ
 *      Author: Administrator
 */

#ifndef HTTPUTIL_H_
#define HTTPUTIL_H_
#include<iostream>
#include<string>
#include<stdint.h>
#include<string.h>
#include <sstream>
using namespace std;
//added by xlf  2014/8/1      parse http protocol from  one complete http session
class httpUtil {
public:
	httpUtil();
	virtual ~httpUtil();
	// begin parse
	int parse_request(const char* source,uint32_t len);
	int parse_response(const char* source,uint32_t len);


 inline	string& get_request_method(){
		return _request_method;
	 }
 inline	string& get_request_url(){
	    return _request_url;
 	 }
 inline	string& get_request_httpType(){
	 return _request_httpType;
 }
 inline	string& get_request_acceptLanguage(){
	 return _request_acceptLanguage;
 }
 inline	string& get_request_referer(){
	 return _request_referer;
 }
 inline	string& get_request_cookie(){
	 return _request_cookie;
 }
 inline	string& get_request_accept(){
	 return _request_accept;
 }
 inline	string& get_request_acceptEncoding(){
	 return _request_acceptEncoding;
 }
 inline	string& get_request_host(){
	 return _request_host;
 }
 inline	string& get_request_payload(){
	 return _request_payload;
 }
 inline string& get_request_userAgent(){
	 return _request_userAgent;
 }

 inline	string& get_response_code(){
	 return _response_code;
 }
 inline	string& get_response_date(){
	 return _response_date;
 }
 inline	string& get_response_contentType(){
	 return _response_contentType;
 }
 inline	string& get_response_transferEncoding(){
	 return _response_transferEncoding;
 }
 inline	string& get_response_contentLength(){
	 return _response_contentLength;
 }
 inline	string& get_response_connection(){
	 return _response_connection;
 }
 inline	string& get_response_payload(){
	 return _response_payload;
 }
private:
 	 void clear_request();
     void clear_response();
     int get_header_field(const char* source,string& field,const char* fieldName);
     int dissect_request_firstLine();
     int dissect_response_firstLine();
     int dissect_response_chunked_transfer_entity(const char* source,uint32_t len);
 	string _request_firstLine;
	string _request_method;
	string _request_url;
	string _request_httpType;
	string _request_acceptLanguage;
	string _request_referer;
	string _request_cookie;
	string _request_accept;
	string _request_acceptEncoding;
	string _request_host;
	string _request_payload;
	string _request_userAgent;

	string _response_firstLine;
	string _response_code;
	string _response_date;
	string _response_contentType;
	string _response_transferEncoding;
	string _response_contentLength;
	string _response_connection;
	string _response_payload;

};

#endif /* HTTPUTIL_H_ */
