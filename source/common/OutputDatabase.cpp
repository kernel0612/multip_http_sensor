/*
 * OutputDatabase.cpp
 *
 *  Created on: 2014Äê8ÔÂ11ÈÕ
 *      Author: Administrator
 */

#include "OutputDatabase.h"

OutputDatabase::OutputDatabase() {
	// TODO Auto-generated constructor stub

}

OutputDatabase::~OutputDatabase() {
	// TODO Auto-generated destructor stub
}

int OutputDatabase::init(){
	return 0;
}
int OutputDatabase::fini(){
	return 0;
}
int OutputDatabase::output(struct RequestInfo* req){
	_cachedReq.push_back(req);
	if(_cachedReq.size()>=threshold){
		struct record  *rec=new record[_cachedReq.size()];
		char* sql="";
		for(;;){
			rec[i]=;
		}
		_pq->copy(sql,rec,_cachedReq.size());
	}
	return 0;
}
int OutputDatabase::output(struct ResponseInfo* rep){
	return 0;
}
