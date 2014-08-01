/*
 * AccessDatabase.h
 *
 *  Created on: 2014Äê8ÔÂ1ÈÕ
 *      Author: Administrator
 */

#ifndef ACCESSDATABASE_H_
#define ACCESSDATABASE_H_
#include"PQ.h"
#include"globalconfig.h"
class AccessDatabase {
public:
	AccessDatabase();
	virtual ~AccessDatabase();

	int create();
	int destroy();


private:
	int update_local_table();
	PQ* _nms_app_obj;
	PQ* _nms_ipaddress;
	PQ* _nms_account_rule;
};

#endif /* ACCESSDATABASE_H_ */
