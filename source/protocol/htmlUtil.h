/*
 * htmlUtil.h
 *
 *  Created on: 2014Äê8ÔÂ8ÈÕ
 *      Author: Administrator
 */

#ifndef HTMLUTIL_H_
#define HTMLUTIL_H_
#include<iostream>
#include<string>
#include"gumbo.h"
using namespace std;
class htmlUtil {
public:
	htmlUtil();
	virtual ~htmlUtil();

	int parse_html(const char* input,int inputlen);
	string& get_html_title();

private:
	GumboOutput* _output;
	string _title;
};

#endif /* HTMLUTIL_H_ */
