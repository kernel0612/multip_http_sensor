/*
 * main.cpp
 *
 *  Created on: 2014��7��21��
 *      Author: Administrator
 */
#include<stdio.h>
#include"httpsensor.h"





int main(int argc,char** argv){


	const char* xml= argc>=2? argv[1] : "../config/all_config.xml";
	http_sensor* sensor=new http_sensor;
	if(sensor->create()<0){
		return -1;
	}
	if(sensor->load_config(xml)<0){
		return -1;
	}
	sensor->run();
	return 0;
}



