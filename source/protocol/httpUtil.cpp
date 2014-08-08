/*
 * httpUtil.cpp
 *
 *  Created on: 2014Äê8ÔÂ1ÈÕ
 *      Author: Administrator
 */

#include "httpUtil.h"

httpUtil::httpUtil() {
	// TODO Auto-generated constructor stub

}

httpUtil::~httpUtil() {
	// TODO Auto-generated destructor stub
}

int httpUtil::parse_request(const char* source,uint32_t len){
	if(!source||len==0){
		return -1;
	}
	clear_request();
	char* pheadEnd=0;
	char* pentity=0;
	pheadEnd=strstr(source,"\r\n\r\n");
	if(pheadEnd==0){
		return -1;
	}
	uint32_t headlen=pheadEnd+4-source;
	pentity=pheadEnd+4;
	if(headlen==0){
		return -1;
	}
	char* headbuff=new char[headlen+1];
	if(!headbuff){
		return -1;
	}
	memset(headbuff,0,headlen+1);
	memcpy(headbuff,source,headlen);
	int getRet=0,PostRet=0;
    getRet=get_header_field(headbuff,_request_firstLine,"GET ");
    PostRet=get_header_field(headbuff,_request_firstLine,"POST ");
    if(getRet==0){
    	_request_method="GET";
    }
    else if(PostRet==0){
    	_request_method="POST";
    }
    get_header_field(headbuff,_request_accept,"Accept: ");
    get_header_field(headbuff,_request_referer,"Referer: ");
    get_header_field(headbuff,_request_acceptEncoding,"Accept-Encoding: ");
    get_header_field(headbuff,_request_userAgent,"User-Agent: ");
    get_header_field(headbuff,_request_host,"Host: ");
    get_header_field(headbuff,_request_cookie,"Cookie: ");
    get_header_field(headbuff,_request_acceptLanguage,"Accept-Language: ");
    get_header_field(headbuff,_request_connection,"Connection: ");
    dissect_request_firstLine();
	uint32_t entitylen=len-headlen;
	if(entitylen==0){
		_request_payload="";
	}
	else
		_request_payload=pentity;
	delete []headbuff;
	return 0;
}
int httpUtil::parse_response(const char* source,uint32_t len){
	if(!source||len==0){
		return -1;
	}
	clear_response();
	char* pheadEnd=strstr(source,"\r\n\r\n");
	if(pheadEnd==0){
		return -1;
	}
	uint32_t  headlen=pheadEnd+4-source;
	if(headlen==0){
		return -1;
	}
	char* headbuff=new char[headlen+1];
	if(!headbuff){
		return -1;
	}
	memset(headbuff,0,headlen+1);
	memcpy(headbuff,source,headlen);
	int contentLenRet=0;
	int transEncodRet=0;
	get_header_field(headbuff,_response_firstLine,"HTTP/");
    get_header_field(headbuff,_response_date,"Date: ");
    contentLenRet=get_header_field(headbuff,_response_contentLength,"Content-Length: ");
    get_header_field(headbuff,_response_contentType,"Content-Type: ");
    get_header_field(headbuff,_response_connection,"Connection: ");
    transEncodRet=get_header_field(headbuff,_response_transferEncoding,"Transfer-Encoding: ");
    dissect_response_firstLine();
	const char* pentity=pheadEnd+4;
	uint32_t entitylen=len-headlen;
    if(contentLenRet==0){
    	_response_payload.append(pentity,entitylen);
    }
    else if(transEncodRet==0){
    	dissect_response_chunked_transfer_entity(pentity,entitylen);
    	uint32_t contentLen=_response_payload.length();
    	ostringstream ost;
    	ost<<contentLen;
    	_response_contentLength=ost.str();

    }
	delete [] headbuff;
	return 0;
}

int httpUtil::get_header_field(const char* source,string& field,const char* fieldName){
	if(!source||!fieldName){
		return -1;
	}
	char* pfield=0;
	char* pfieldEnd=0;
    pfield=strstr(source,fieldName);
    if(pfield){
    	pfield+=strlen(fieldName);
    	pfieldEnd=strstr(pfield,"\r\n");
    	if(pfieldEnd){
    		uint32_t fieldStrLen=pfieldEnd-pfield;
    		field.append(pfield,fieldStrLen);
    		return 0;
    	}
    }
	return -1;
}
int httpUtil::dissect_request_firstLine(){
	if(_request_firstLine.empty()){
	    return -1;
	}
    stringstream  ss(_request_firstLine);
    string resource,httptype;
    ss>>resource>>httptype;
    if(resource.empty()||httptype.empty()){
    	return -1;
    }
    _request_httpType=httptype;
    if(_request_host.empty()){
    	return -1;
    }
    _request_url.append("http://");
    _request_url.append(_request_host);
    _request_url.append(resource);
	return 0;
}
int httpUtil::dissect_response_firstLine(){
    if(_response_firstLine.empty){
    	return -1;
    }
    stringstream ss(_response_firstLine);
    string httptype,resCode,resDis;
    ss>>httptype>>resCode>>resDis;
    if(resCode.empty()||resDis.empty()){
    	return -1;
    }
    _response_code.append(resCode);
	return 0;
}
int httpUtil::dissect_response_chunked_transfer_entity(const char* source,uint32_t len){
	if(!source||len==0){
		return -1;
	}
    const char* pstart=source;
    char* ptemp=0;
    uint32_t nchunkSize=0;
    char chunkSizebuff[32]={0};
    do{
    	ptemp=strstr(pstart,"\r\n");
    	if(ptemp){
    		memset(chunkSizebuff,0,32);
    		memcpy(chunkSizebuff,pstart,ptemp-pstart);
    		nchunkSize=strtol(chunkSizebuff,NULL,16);
    		if(nchunkSize==0){
    			break;
    		}
    		_response_payload.append(pstart,nchunkSize);
    		pstart=ptemp;
    		pstart+=2;
    	}
    	else
    		break;
    }while(nchunkSize&&((pstart-source)<=len));
	return 0;
}
void httpUtil::clear_request(){
 	_request_firstLine="";
	_request_method="";
	_request_url="";
	_request_httpType="";
	_request_acceptLanguage="";
	_request_referer="";
	_request_cookie="";
	_request_accept="";
	_request_acceptEncoding="";
	_request_host="";
	_request_connection="";
	_request_payload="";
	_request_userAgent="";
}
void httpUtil::clear_response(){
	_response_firstLine="";
	_response_code="";
	_response_date="";
	_response_contentType="";
	_response_transferEncoding="";
	_response_contentLength="";
	_response_connection="";
	_response_payload="";
}
