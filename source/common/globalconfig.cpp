/*
 * globalconfig.cpp
 *
 *  Created on: 2014Äê7ÔÂ21ÈÕ
 *      Author: Administrator
 */

#include "globalconfig.h"

namespace configure {

ACE_Thread_Mutex global_config::_mutex;
global_config* global_config::_instance=0;
global_config* global_config::get_instance(){
	if(_instance==0){
		_mutex.acquire(0);
		if(_instance==0){
			_instance=new global_config;
		}
		_mutex.release();
	}
	return _instance;
}
void global_config::destroy_instance(){
	if(_instance){
		_mutex.acquire(0);
		delete _instance;
		_instance=0;
		_mutex.release();
	}
}
void global_config::load_config(const char* xml_path){

}
global_config::global_config():
		_bdb_cache_size(0),
		_bdb_page_size(0),_bdb_deadlock_detect_val(0),
		_bdb_re_len(0),_bdb_q_extent_size(0),
		_pgsl_port(0),_pgsl_conn_timeout(0){
	// TODO Auto-generated constructor stub

}

global_config::~global_config() {
	// TODO Auto-generated destructor stub
}

} /* namespace configure */
