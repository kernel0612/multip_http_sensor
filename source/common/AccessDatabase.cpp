/*
 * AccessDatabase.cpp
 *
 *  Created on: 2014Äê8ÔÂ1ÈÕ
 *      Author: Administrator
 */

#include "AccessDatabase.h"

AccessDatabase::AccessDatabase() {
	// TODO Auto-generated constructor stub
	_nms_app_obj=0;
	_nms_ipaddress=0;
	_nms_account_rule=0;
}

AccessDatabase::~AccessDatabase() {
	// TODO Auto-generated destructor stub
	destroy();
}
int AccessDatabase::create(){
	if(_nms_app_obj==0){
		_nms_app_obj=new PQ("ip",111,"dbname","usrname","password",10);
		if(_nms_app_obj){
			int ret=_nms_app_obj->connect();
			if(ret<0){
				return -1;
			}
		}
		else
			return -1;
	}
	if(_nms_ipaddress==0){
		_nms_ipaddress=new PQ("ip",111,"dbname","usrname","password",10);
		if(_nms_ipaddress){
			int ret=_nms_ipaddress->connect();
			if(ret<0){
				return -1;
			}
		}
		else
			return -1;
	}
	if(_nms_account_rule==0){
		_nms_account_rule=new PQ("ip",111,"dbname","usrname","password",10);
		if(_nms_account_rule){
			int ret=_nms_account_rule->connect();
			if(ret<0){
				return -1;
			}
		}
		else
			return -1;
	}
	return 0;
}
int AccessDatabase::destroy(){
	if(_nms_app_obj){
		_nms_app_obj->disconnect();
		delete _nms_app_obj;
		_nms_app_obj=0;
	}
	if(_nms_ipaddress){
		_nms_ipaddress->disconnect();
		delete _nms_ipaddress;
		_nms_ipaddress=0;
	}
	if(_nms_account_rule){
		_nms_account_rule->disconnect();
		delete _nms_account_rule;
		_nms_account_rule=0;
	}
	return -1;
}
int  AccessDatabase::update_local_table(){
	return -1;
}
