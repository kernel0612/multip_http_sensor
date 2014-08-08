/*
 * AccessDatabase.cpp
 *
 *  Created on: 2014Äê8ÔÂ1ÈÕ
 *      Author: Administrator
 */

#include "AccessDatabase.h"

AccessDatabase::AccessDatabase() {
	// TODO Auto-generated constructor stub
	//_nms_app_obj=0;
	//_nms_ipaddress=0;
	//_nms_account_rule=0;
	_nms_app_obj_conn=0;
	_nms_ipaddress_conn=0;
	_nms_account_rule_conn=0;
	_app_obj_db_isOpen=0;
	_ipaddress_db_isOpen=0;
	_account_rule_db_isOpen=0;
}

AccessDatabase::~AccessDatabase() {
	// TODO Auto-generated destructor stub
	destroy();
}
int AccessDatabase::create(){
//	if(_nms_app_obj==0){
//		_nms_app_obj=new PQ("ip",111,"dbname","usrname","password",10);
//		if(_nms_app_obj){
//			int ret=_nms_app_obj->connect();
//			if(ret<0){
//				return -1;
//			}
//			_app_obj_db_isOpen=1;
//		}
//		else
//			return -1;
//	}
//	if(_nms_ipaddress==0){
//		_nms_ipaddress=new PQ("ip",111,"dbname","usrname","password",10);
//		if(_nms_ipaddress){
//			int ret=_nms_ipaddress->connect();
//			if(ret<0){
//				return -1;
//			}
//			_ipaddress_db_isOpen=1;
//		}
//		else
//			return -1;
//	}
//	if(_nms_account_rule==0){
//		_nms_account_rule=new PQ("ip",111,"dbname","usrname","password",10);
//		if(_nms_account_rule){
//			int ret=_nms_account_rule->connect();
//			if(ret<0){
//				return -1;
//			}
//			_account_rule_db_isOpen=1;
//		}
//		else
//			return -1;
//	}
	try{
		configure::global_config* config=configure::global_config::get_instance();
	    char* conn_info=format_connect_info("ip",11,"dbna","user","pass",1);
		_nms_app_obj_conn=new connection(conn_info);
		if(_nms_app_obj_conn->is_open()){
			_app_obj_db_isOpen=1;
		}
		else{
			return -1;
		}
	     conn_info=format_connect_info("ip",11,"dbna","user","pass",1);
		_nms_ipaddress_conn=new connection(conn_info);
		if(_nms_ipaddress_conn->is_open()){
			_ipaddress_db_isOpen=1;
		}
		else{
			return -1;
		}
		conn_info=format_connect_info("ip",11,"dbna","user","pass",1);
		_nms_account_rule_conn=new connection(conn_info);
		if(_nms_account_rule_conn->is_open()){
			_account_rule_db_isOpen=1;
		}
		else{
			return -1;
		}
	}
	catch(...){
		delete _nms_app_obj_conn;
		_nms_app_obj_conn=0;
		delete _nms_ipaddress_conn;
		_nms_ipaddress_conn=0;
		delete _nms_account_rule_conn;
		_nms_account_rule_conn=0;
	}

	pthread_create(&_thread_timer, NULL, on_timer, this);
	return 0;
}
int AccessDatabase::destroy(){
//	if(_nms_app_obj){
//		_nms_app_obj->disconnect();
//		delete _nms_app_obj;
//		_nms_app_obj=0;
//		_app_obj_db_isOpen=0;
//	}
//	if(_nms_ipaddress){
//		_nms_ipaddress->disconnect();
//		delete _nms_ipaddress;
//		_nms_ipaddress=0;
//		_ipaddress_db_isOpen=0;
//	}
//	if(_nms_account_rule){
//		_nms_account_rule->disconnect();
//		delete _nms_account_rule;
//		_nms_account_rule=0;
//		_account_rule_db_isOpen=0;
//	}
	if(_nms_app_obj_conn){
		_nms_app_obj_conn->disconnect();
		delete _nms_app_obj_conn;
		_nms_app_obj_conn=0;
		_app_obj_db_isOpen=0;
	}
	if(_nms_ipaddress_conn){
		_nms_ipaddress_conn->disconnect();
		delete _nms_ipaddress_conn;
		_nms_ipaddress_conn=0;
		_ipaddress_db_isOpen=0;
	}
	if(_nms_account_rule_conn){
		_nms_account_rule_conn->disconnect();
		delete _nms_account_rule_conn;
		_nms_account_rule_conn=0;
		_account_rule_db_isOpen=0;
	}
    pthread_cancel(_thread_timer);
    pthread_join(_thread_timer, NULL);
	return 0;
}
int  AccessDatabase::update_local_table(){
	if(_app_obj_db_isOpen){
		work wk(*_nms_app_obj_conn);
		string sql="SELECT * FROM nms_app_obj";
		result r=wk.exec(sql);
		_nms_app_obj_conn.->set_client_encoding("GBK");

	    for (result::const_iterator row = r.begin(); row != r.end(); ++row)
		{
	    	vector<string> vs;
			for (tuple::const_iterator field = row->begin();
				field != row->end();
				++field){
				string fie(field.c_str());
				vs.push_back(fie);
			}
			if(vs.size()>=10){
				nms_app_obj ob;
                copy_data(ob,vs);
				std::map<char*,struct nms_app_obj>::iterator it;
				it=_app_obj_map.find(ob.app_uuid);
				if(it!=_app_obj_map.end()){
					nms_app_obj finded_obj=it->second;
		            copy_data(finded_obj,vs);
				}
				else{
					_app_obj_map.insert(make_pair(ob.app_uuid,ob));
				}
			}

		}
	}
	if(_ipaddress_db_isOpen){
		work wk(*_nms_ipaddress_conn);
		string sql="SELECT * FROM nms_ipaddress";
		result r=wk.exec(sql);
		_nms_ipaddress_conn->set_client_encoding("GBK");

	    for (result::const_iterator row = r.begin(); row != r.end(); ++row)
		{
	    	vector<string> vs;
			for (tuple::const_iterator field = row->begin();
				field != row->end();
				++field){
				string fie(field.c_str());
				vs.push_back(fie);
			}
			if(vs.size()>=7){
				nms_ipaddress ob;
                copy_data(ob,vs);
				std::map<char*,struct nms_ipaddress>::iterator it;
				it=_app_obj_map.find(ob.ipaddress_uuid);
				if(it!=_app_obj_map.end()){
					nms_ipaddress finded_obj=it->second;
		            copy_data(finded_obj,vs);
				}
				else{
					_app_obj_map.insert(make_pair(ob.ipaddress_uuid,ob));
				}
			}

		}
	}
	if(_account_rule_db_isOpen){
		work wk(*_nms_ipaddress_conn);
		string sql="SELECT * FROM nms_account_rule";
		result r=wk.exec(sql);
		_nms_account_rule_conn->set_client_encoding("GBK");

	    for (result::const_iterator row = r.begin(); row != r.end(); ++row)
		{
	    	vector<string> vs;
			for (tuple::const_iterator field = row->begin();
				field != row->end();
				++field){
				string fie(field.c_str());
				vs.push_back(fie);
			}
			if(vs.size()>=11){
				nms_account_rule ob;
                copy_data(ob,vs);
				std::map<char*,struct nms_account_rule>::iterator it;
				it=_account_rule_map.find(ob.accrule_uuid);
				if(it!=_account_rule_map.end()){
					nms_account_rule finded_obj=it->second;
		            copy_data(finded_obj,vs);
				}
				else{
					_account_rule_map.insert(make_pair(ob.accrule_uuid,ob));
				}
			}

		}
	}
	return -1;
}
void* AccessDatabase::on_timer(void* p){
	AccessDatabase* pthis=(AccessDatabase*)p;
	struct timeval tempval;
	tempval.tv_sec = 300;
	tempval.tv_usec = 0;
	while(1){
		pthis->update_local_table();
		select(0, NULL, NULL, NULL, &tempval);
	}
}
char* AccessDatabase::format_connect_info(const char *ip, uint16_t pport, const char *pdbname,
		const char *puser, const char *ppasswd, int pconnect_timeout){
	memset(format,0,sizeof(format));
	  snprintf(format, sizeof(format) - 1, "hostaddr='%s' port='%d' dbname='%s' user='%s' password='%s' connect_timeout=%d", \
			  ip, pport, pdbname, puser, ppasswd, pconnect_timeout);
	return format;
}

int AccessDatabase::copy_data(struct nms_app_obj& inObj,const vector<string>& src){
	if(src.size()>=10){
		memset(&inObj,0,sizeof(struct nms_app_obj));
		memcpy(inObj.app_uuid,src[0].c_str(),128);
		memcpy(inObj.app_name,src[1].c_str(),128);
		memcpy(inObj.app_code,src[2].c_str(),128);
		memcpy(inObj.parent_id,src[3].c_str(),128);
		memcpy(inObj.level,src[4].c_str(),128);
		memcpy(inObj.app_ip,src[5].c_str(),128);
		memcpy(inObj.app_port,src[6].c_str(),128);
		memcpy(inObj.app_protocol,src[7].c_str(),128);
		memcpy(inObj.app_url,src[8].c_str(),500);
		memcpy(inObj.app_status,src[9].c_str(),128);
		return 0;
	}
	return -1;
}
int AccessDatabase::copy_data(struct nms_ipaddress& inObj,const vector<string>& src){
	if(src.size()>=7){
		memset(&inObj,0,sizeof(struct nms_ipaddress));
		memcpy(inObj.ipaddress_uuid,src[0].c_str(),128);
		memcpy(inObj.ip_start,src[1].c_str(),128);
		memcpy(inObj.ip_end,src[2].c_str(),128);
		memcpy(inObj.ip_address,src[3].c_str(),64);
		memcpy(inObj.ip_business,src[4].c_str(),64);
		memcpy(inObj.ip_start_value,src[5].c_str(),38);
		memcpy(inObj.ip_end_value,src[6].c_str(),38);
		return 0;
	}
	return -1;
}
int AccessDatabase::copy_data(struct nms_account_rule& inObj,const vector<string>& src){
	if(src.size()>=11){
		memset(&inObj,0,sizeof(struct nms_account_rule));
		memcpy(inObj.accrule_uuid,src[0].c_str(),128);
		memcpy(inObj.app_uuid,src[1].c_str(),128);
		memcpy(inObj.server_ip,src[2].c_str(),500);
		memcpy(inObj.domain_ip,src[3].c_str(),128);
		memcpy(inObj.page_url,src[4].c_str(),128);
		memcpy(inObj.param_get,src[5].c_str(),500);
		memcpy(inObj.param_post,src[6].c_str(),500);
		memcpy(inObj.cookie,src[7].c_str(),500);
		memcpy(inObj.domain_mode,src[8].c_str(),16);
		memcpy(inObj.url_mode,src[9].c_str(),16);
		memcpy(inObj.rule_content,src[10].c_str(),2000);
		return 0;
	}
	return -1;
}
