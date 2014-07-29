#ifndef MY_BERKELEYDB_H
#define MY_BERKELEYDB_H
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
using namespace std;
#define  DBHOME "/home/xlf/bdbdata"
class my_berkeleyDB
{
public:
	my_berkeleyDB(void);
	~my_berkeleyDB(void);
	int open(const char* dbname,DBTYPE type);
	int close();
	int put(char* key,int keySize,void* value,int valueSize);
	int put(void* value,int valueSize);
	int get(char* key,int keySize,void** value,int* valueSize);
	int get(void** value,int* valueSize);


	void init_bdb_settings();
	void init_bdb_env();
	void close_bdb_env_db();
	void start_deadlock_detect_thread();
	static void bdb_err_callback(const DB_ENV *dbenv, const char *errpfx, const char *msg);
	static void bdb_msg_callback(const DB_ENV *dbenv, const char *msg);
	static void *bdb_deadlock_detect_thread(void *arg);

private:
	DB* _db;
	DB_ENV* _env;
	int _bclose;
	int _bopen;

	char *env_home;
	u_int32_t cache_size;
	u_int32_t txn_lg_bsize;
	u_int32_t log_auto_remove;
	u_int32_t page_size;
	int txn_nosync;
	int deadlock_detect_val;
	int checkpoint_val;
	int mempool_trickle_val;
	int mempool_trickle_percent;
	int qstats_dump_val;
	u_int32_t re_len;
	u_int32_t q_extentsize;

};
#endif