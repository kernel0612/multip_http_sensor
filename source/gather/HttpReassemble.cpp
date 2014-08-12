/*
 * HttpReassemble.cpp
 *
 *  Created on: 2014年8月8日
 *      Author: Administrator
 */

#include "HttpReassemble.h"

HttpReassemble::HttpReassemble() {
	// TODO Auto-generated constructor stub

}

HttpReassemble::~HttpReassemble() {
	// TODO Auto-generated destructor stub
}

int HttpReassemble::process_httpfrag(struct httpfrag* frag,struct http_interaction** defrag)      //0 complete  1 not complete   -1 error
{
	if(!frag||!defrag){
		return -1;
	}
	int ret=0;
    if(frag->type==responsefrag){
		if(is_frag_need_drop(frag)){
			return 1;
		}
		std::map<struct fragKey,struct http_interaction >::iterator iit=
		_interation_table.find(frag->key);
		if(iit==_interation_table.end()){
			return 1;
		}
		http_interaction hi=iit->second;
		hi.response.push_back(frag);
		if(is_response_done()){
			return 0;
		}
    }
    else if(frag->type==requestfrag){
    	if((ret=is_first_request_frag(frag))){
      		if(is_frag_need_drop(frag)){
      			return 1;
        	}
    		// new to map
    		http_interaction hi;
    		hi.response.push_back(frag);
    		_interation_table.insert(make_pair(frag->key,hi));
    	}
    	else if(!ret){    //update interaction in map
      		if(is_frag_need_drop(frag)){
            	return 1;
            }
    		std::map<struct fragKey,struct http_interaction >::iterator iit=
    		_interation_table.find(frag->key);
    		if(iit==_interation_table.end()){
    			return 1;
    		}
    		http_interaction hi=iit->second;
    		hi.request.push_back(frag);
    	}
    	else{
    		return -1;
    	}
    }
    else{
    	return -1;
    }
	return 0;
}

int HttpReassemble::is_first_response_frag(struct httpfrag* frag)   // 包含 HTTP/1.1 200 OK 的包 ret 1  or return 0 -1 error
{
	if(!frag){
		return -1;
	}
	char* pheadbuf=0;
	int  headlen=0;
	char* presMethod=0;
	char* pheadEnd=strstr(frag->frag,"\r\n\r\n");
	if(pheadEnd){
		headlen=pheadEnd-frag->frag+4;
		if(headlen<=0){
			return -1;
		}
		pheadbuf=new char[headlen+1];
		if(!pheadbuf){
			return -1;
		}
		memset(pheadbuf,0,headlen+1);
		memcpy(pheadbuf,frag->frag,headlen);
		if(strstr(pheadbuf,"HTTP/")){
			delete [] pheadbuf;
			return 1;
		}
		delete [] pheadbuf;
	}
	else{
		return 0;
	}

	return 0;
}
int HttpReassemble::is_first_request_frag(struct httpfrag* frag){
	if(!frag){
		return -1;
	}
	char* pheadbuf=0;
	int  headlen=0;
	char* presMethod=0;
	char* pheadEnd=strstr(frag->frag,"\r\n\r\n");
	if(pheadEnd){
		headlen=pheadEnd-frag->frag+4;
		if(headlen<=0){
			return -1;
		}
		pheadbuf=new char[headlen+1];
		if(!pheadbuf){
			return -1;
		}
		memset(pheadbuf,0,headlen+1);
		memcpy(pheadbuf,frag->frag,headlen);
		if(strstr(pheadbuf,"GET")||strstr(pheadbuf,"POST")){
			delete [] pheadbuf;
			return 1;
		}
		delete [] pheadbuf;
	}
	else{
		return 0;
	}
	return 0;
}
int HttpReassemble::get_response_len(struct httpfrag* frag)   //从 首个响应包中的content-length中获取
{
	if(!frag){
		return -1;
	}
	if(!frag->frag||!frag->fraglen){
		return -1;
	}
	string field("");
    int ret=get_header_field(frag->frag,field,"Content-Length: ");
    if(ret==0){
    	return atoi(field.c_str());
    }
	return -1;
}
int HttpReassemble::is_chunked_reponse(struct httpfrag* frag){
	if(!frag){
		return -1;
	}
	if(!frag->frag||!frag->fraglen){
		return -1;
	}
	string field("");
	int ret=get_header_field(frag->frag,field,"Transfer-Encoding: ");
	if(ret==0){
		return 1;
	}
	return 0;
}
int HttpReassemble::is_response_done(){
	return 0;
}
int HttpReassemble::is_request_done(){
	return 0;
}
char* HttpReassemble::response_glue(){
	return 0;
}
char* HttpReassemble::request_glue(){
	return 0;
}

int HttpReassemble::get_header_field(const char* source,string& field,const char* fieldName){
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

int HttpReassemble::if_finded_erase_it(struct fragKey& key){
	set<struct fragKey>::iterator it=_drop_requests.begin();
	for(;it!=_drop_requests.end();){
		if(*it==key){
			it=_drop_requests.erase(it);
			return 0;
		}
		else{
			++it;
		}
	}
	return -1;
}
int HttpReassemble::process_interaction_status(struct fragKey& key,uint32_t status){
	switch(status){
	case interaction_close:
	case interaction_rst:
	case interaction_timeout:
		if_finded_erase_it(key);
		break;
	case interaction_begin:
	case interaction_update:
		break;
	default:
		//err
		break;

	}
	return 0;
}
int HttpReassemble::is_frag_need_drop(struct httpfrag* frag){
	if(!frag){
		return -1;
	}
	//利用配置的规则
	if(1){
		_drop_requests.insert(frag->key);
		return 1;
	}
	return 0;
}

