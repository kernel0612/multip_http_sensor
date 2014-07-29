/*
 * globalconfig.h
 *
 *  Created on: 2014Äê7ÔÂ21ÈÕ
 *      Author: Administrator
 */

#ifndef GLOBALCONFIG_H_
#define GLOBALCONFIG_H_
#include"ace/Synch.h"

namespace configure {

class global_config {
public:
	global_config();

    static global_config* get_instance();
    static void destroy_instance();
    static void load_config(const char* xml_path);

public:

	//fifo config

	char* _bdb_outputdb_home;
	char* _bdb_capteddb_home;
	unsigned int _bdb_cache_size;
	unsigned int _bdb_page_size;
	unsigned int _bdb_deadlock_detect_val;
	unsigned int _bdb_re_len;
	unsigned int _bdb_q_extent_size;
	//end of fifo config

	//postgreSQL config
	char* _pgsl_db_name;
	char* _pgsl_loginName;
	char* _pgsl_passWord;
	char* _pgsl_hostName;
	unsigned short _pgsl_port;
	unsigned short _pgsl_conn_timeout;
	//end of postgreSQL config;

	//ssdb config
     char* _ssdb_ip;
     unsigned short _ssdb_port;
	//end of ssdb config

	//log config
	char* _log_home;
	//end of log config

private:
	virtual ~global_config();
	static ACE_Thread_Mutex _mutex;
	static global_config* _instance;

};

} /* namespace configure */

#endif /* GLOBALCONFIG_H_ */
