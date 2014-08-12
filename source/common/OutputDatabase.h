/*
 * OutputDatabase.h
 *
 *  Created on: 2014年8月11日
 *      Author: Administrator
 */

#ifndef OUTPUTDATABASE_H_
#define OUTPUTDATABASE_H_
#include<vector>
#include "PQ.h"
#include "commondef.h"
using namespace std;
class OutputDatabase {
public:
	OutputDatabase();
	virtual ~OutputDatabase();

	int init();
	int fini();
	int output(struct RequestInfo* req);
	int output(struct ResponseInfo* rep);

private:

	int format_result(struct RequestInfo* req); //去除 信息中的 \r \n \t
	int format_result(struct ResponseInfo* rep);
	int threshold;
	vector<struct RequestInfo* > _cachedReq;
	vector<struct ResponseInfo* > _cachedRep;
	PQ* _pq;
};

#endif /* OUTPUTDATABASE_H_ */
