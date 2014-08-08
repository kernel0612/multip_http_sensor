/*
 * httpRequestFilter.h
 *
 *  Created on: 2014Äê8ÔÂ8ÈÕ
 *      Author: Administrator
 */

#ifndef HTTPREQUESTFILTER_H_
#define HTTPREQUESTFILTER_H_
#include<stdio.h>
#include<stdlib.h>
#include<iostream>
#include<string>
using namespace std;
class httpRequestFilter {
public:
	httpRequestFilter();
	virtual ~httpRequestFilter();
	int load_filter_rule();
	int needed_filter(const char* source,int len);    //1 true   0 false


private:
	string _rule;
};

#endif /* HTTPREQUESTFILTER_H_ */
