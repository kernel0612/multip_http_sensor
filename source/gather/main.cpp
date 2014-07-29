/*
 * main.cpp
 *
 *  Created on: 2014Äê7ÔÂ21ÈÕ
 *      Author: Administrator
 */
#include<stdio.h>
#include"httpsensor.h"





int main(int argc,char** argv){


	const char* xml= argc>=2? argv[1] : "../config/all_config.xml";
	http_sensor* sensor=new http_sensor;
	if(sensor->create()<0){
		ACE_DEBUG((LM_ERROR,"http_sensor create object failed."));
		return -1;
	}
	//sensor->load_config(xml);
	sensor->run();
	return 0;
}



