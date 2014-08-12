/*
 * AccessDatabase.h
 *
 *  Created on: 2014Äê8ÔÂ1ÈÕ
 *      Author: Administrator
 */

#ifndef ACCESSDATABASE_H_
#define ACCESSDATABASE_H_
#include<iostream>
#include<map>
#include<string>
#include<vector>
#include <pthread.h>
#include <sys/time.h>
#include <sys/select.h>
//#include"PQ.h"
#include"globalconfig.h"
#include"commondef.h"
#include"globalconfig.h"
#include <pqxx/pqxx>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
using namespace std;
using namespace pqxx;
class AccessDatabase {
public:
	AccessDatabase();
	virtual ~AccessDatabase();

	int create();
	int destroy();

	int get_ipaddressAndipbusiness(string& inputIP,string& matchedIPaddr,string& matchedIPbusi);
	int get_resname_rescode_appuuid(string& inputurl,string& inputIP,string& matchedresname,
			string& matchedrescode,string& matcheduuid);
	int get_rule_content(string& appuuid,string& matchedrule);


private:
	pthread_t _thread_timer;
	static void* on_timer(void* p);
	int update_local_table();
	char* format_connect_info(const char *ip, uint16_t pport, const char *pdbname,
			const char *puser, const char *ppasswd, int pconnect_timeout);

	int copy_data(struct nms_app_obj& inObj,const vector<string>& src);
	int copy_data(struct nms_ipaddress& inObj,const vector<string>& src);
	int copy_data(struct nms_account_rule& inObj,const vector<string>& src);

	int compare_ip(const char* ip1,const char* ip2);
	int clear_app_obj_map();
	int clear_ipaddress_map();
	int clear_accountrule_map();



	connection*  _nms_app_obj_conn;
	connection*  _nms_ipaddress_conn;
	connection*  _nms_account_rule_conn;
	int _app_obj_db_isOpen;
	int _ipaddress_db_isOpen;
	int _account_rule_db_isOpen;
	char format[512];

	std::map<char*,struct nms_app_obj> _app_obj_map;
	std::map<char*,struct nms_ipaddress> _ipaddress_map;
	std::map<char*,struct nms_account_rule> _account_rule_map;

	pthread_mutex_t  _mutex;
};

#endif /* ACCESSDATABASE_H_ */
