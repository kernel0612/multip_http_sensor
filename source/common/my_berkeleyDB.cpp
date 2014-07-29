#include "my_berkeleyDB.h"

my_berkeleyDB::my_berkeleyDB(void)
{
	_db=0;
	_env=0;
	_quit=0;
	env_home=DBHOME;
	cache_size=1024*1024;
	txn_lg_bsize=32*1024;
	log_auto_remove=0;
	page_size=4096;
	txn_nosync=0;
	deadlock_detect_val=100*1000;
	checkpoint_val=5*60;
	mempool_trickle_val=30;
	mempool_trickle_percent=60;
	qstats_dump_val=30;
	re_len=2048;
	q_extentsize=16*1024;
	_tid=0;
}

my_berkeleyDB::~my_berkeleyDB(void)
{
	this->close();
}

int my_berkeleyDB::open(const char* dbname,DBTYPE type)
{
	if (!dbname)
	{
		//err
		return -1;
	}
	int ret=0;
	init_bdb_settings();
	init_bdb_env();
	if (ret=db_create(&_db,_env,0)!=0)
	{
		fprintf(stderr, "db_env_create: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (ret=_db->set_re_len(_db, re_len) != 0)
	{
		fprintf(stderr, "db_set_re_len: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (ret=_db->set_re_pad(_db, (int)0x00) != 0)
	{
		fprintf(stderr, "db_set_re_pad: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (ret=_db->set_q_extentsize(_db, q_extentsize) != 0)
	{
		fprintf(stderr, "db_set_q_extentsize: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (ret=_db->set_pagesize(_db,page_size)!=0)
	{
		fprintf(stderr, "db_set_pagesize: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	if (ret=_db->open(_db,NULL,dbname,NULL,type,DB_CREATE,0664)!=0)  
	{
		fprintf(stderr, "db_open: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	deadlock_detect_val=100*1000;
	start_deadlock_detect_thread();
	return 0;
}
int my_berkeleyDB::close()
{
	_quit=1;
	void* ret;
	pthread_join(_tid,&ret);
    close_bdb_env_db();
	return 0;
}
int my_berkeleyDB::put(char* key,int keySize,void* value,int valueSize)
{
	if (!key||keySize<=0||!value||valueSize<=0)
	{
		return -1;
	}

	int ret;
	DBT dbtKey,dbtValue;
	memset(&dbtKey,0,sizeof(DBT));
	memset(&dbtValue,0,sizeof(DBT));
	dbtKey.data=key;
	dbtKey.size=keySize;
	dbtValue.data=value;
	dbtValue.size=valueSize;
	if ((ret=_db->put(_db,NULL,&dbtKey,&dbtValue,0))==0)
	{
		//cout <<"key value stored"<<endl;
	}
	else
	{
		_db->err(_db,ret,"%s","db->put()");
	}
	return ret;
}
int my_berkeleyDB::put(void* value,int valueSize)
{
	if (!value||valueSize<=0)
	{
		return -1;
	}
	int ret;
	DBT dbtKey,dbtValue;
	db_recno_t rec;
	memset(&dbtKey,0,sizeof(DBT));
	memset(&dbtValue,0,sizeof(DBT));
	dbtKey.data=&rec;
	dbtKey.size=sizeof(db_recno_t);
	dbtValue.data=value;
	dbtValue.size=valueSize;
	if ((ret=_db->put(_db,NULL,&dbtKey,&dbtValue,DB_APPEND))==0)
	{
		//cout <<"key value stored"<<endl;
	}
	else
	{
		_db->err(_db,ret,"%s","db->put()");
	}
	return ret;
}
int my_berkeleyDB::get(void** value,int* valueSize)
{
	if (!value||valueSize<=0)
	{
		return -1;
	}

	int ret=0;
	DBT dbtKey,dbtValue;
	db_recno_t rec;
	memset(&dbtKey,0,sizeof(DBT));
	memset(&dbtValue,0,sizeof(DBT));
	dbtKey.data=&rec;
	dbtKey.size=sizeof(db_recno_t);
	if ((ret=_db->get(_db,NULL,&dbtKey,&dbtValue,DB_CONSUME))==0)
	{
		*value=dbtValue.data;
		*valueSize=dbtValue.size;
	}
//	else
//	{
//		_db->err(_db,ret,"%s","db->get()");
//	}
	return ret;
}
int my_berkeleyDB::get(char* key,int keySize,void** value,int* valueSize)
{
	if (!key||keySize<=0||!value||valueSize<=0)
	{
		return -1;
	}
	int ret=0;
	DBT dbtKey,dbtValue;
	memset(&dbtKey,0,sizeof(DBT));
	memset(&dbtValue,0,sizeof(DBT));
	dbtKey.data=key;
	dbtKey.size=keySize;
	if ((ret=_db->get(_db,NULL,&dbtKey,&dbtValue,0))==0)
	{
	    *value=dbtValue.data;
		*valueSize=dbtValue.size;
	}
	return ret;
}

void my_berkeleyDB::bdb_err_callback(const DB_ENV *dbenv, const char *errpfx, const char *msg){
	time_t curr_time = time(NULL);
	char time_str[32];
	strftime(time_str, 32, "%c", localtime(&curr_time));
	fprintf(stderr, "[%s] [%s] \"%s\"\n", errpfx, time_str, msg);
}

void my_berkeleyDB::bdb_msg_callback(const DB_ENV *dbenv, const char *msg){
	time_t curr_time = time(NULL);
	char time_str[32];
	strftime(time_str, 32, "%c", localtime(&curr_time));
	fprintf(stderr, "[berkeleyDB] [%s] \"%s\"\n",time_str, msg);
}
void my_berkeleyDB::init_bdb_settings()
{
	env_home=DBHOME;
	cache_size=1024*1024;
	txn_lg_bsize=32*1024;
	log_auto_remove=0;
	page_size=4096;
	txn_nosync=0;
	deadlock_detect_val=100*1000;
	checkpoint_val=5*60;
	mempool_trickle_val=30;
	mempool_trickle_percent=60;
	qstats_dump_val=30;
	re_len=2048;
	q_extentsize=16*1024;
}
void my_berkeleyDB::init_bdb_env()
{
	int ret;
	u_int32_t env_flags = 
	DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN;
	if ((ret = db_env_create(&_env, 0)) != 0)
	{
		fprintf(stderr, "db_env_create: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
	_env->set_errcall(_env, bdb_err_callback);
    _env->set_msgcall(_env, bdb_msg_callback);
	_env->set_cachesize(_env, 0,cache_size, 0);
	if (txn_nosync)
	{
		_env->set_flags(_env, DB_TXN_NOSYNC, 1);
	}
	if (log_auto_remove) 
	{
		_env->log_set_config(_env, DB_LOG_AUTO_REMOVE, 1);        
	}
	_env->set_lk_max_lockers(_env, 40000);
	_env->set_lk_max_locks(_env, 40000);
	_env->set_lk_max_objects(_env, 40000);
	_env->set_tx_max(_env, 40000);
	_env->set_lg_bsize(_env, txn_lg_bsize);

	//if no home dir existed, we create it 
		if (0 != access(env_home, F_OK)) 
		{
			if (0 != mkdir(env_home, 0750)) 
			{
				fprintf(stderr, "mkdir env_home error:[%s]\n",env_home);
				exit(EXIT_FAILURE);
			}
		}
	if ((ret = _env->open(_env, env_home, env_flags, 0664)) != 0) {
		fprintf(stderr, "_env->open: %s\n", db_strerror(ret));
		exit(EXIT_FAILURE);
	}
}
void my_berkeleyDB::close_bdb_env_db()
{
	int ret = 0;
	if (_db!=NULL)
	{
		ret=_db->close(_db,0);
		if (ret!=0)
		{
			fprintf(stderr, "_db->close: %s\n", db_strerror(ret));
		}
		else
		{
			_db = NULL;
			fprintf(stderr, "_db->close: OK\n");
		}
	}
	if (_env != NULL) 
	{
		ret = _env->close(_env, 0);
		if (0 != ret)
		{
			fprintf(stderr, "_env->close: %s\n", db_strerror(ret));
		}
		else
		{
			_env = NULL;
			fprintf(stderr, "_env->close: OK\n");
		}
	}
}

void my_berkeleyDB::start_deadlock_detect_thread()
{
	if (deadlock_detect_val > 0)
	{
		if ((errno = pthread_create(&_tid, NULL, bdb_deadlock_detect_thread, (void *)this)) != 0)
		{
				fprintf(stderr,
					"failed spawning deadlock thread: %s\n",
					strerror(errno));
				exit(EXIT_FAILURE);
		}
	}
}
void * my_berkeleyDB::bdb_deadlock_detect_thread(void *arg)
{
	my_berkeleyDB* pthis=(my_berkeleyDB*)arg;
	DB_ENV *dbenv=0;
	struct timeval t;
	dbenv = pthis->_env;
	int ret=0;
	fprintf(stderr, "db deadlock detect thread begin\n");
	while (!pthis->_quit) {
		t.tv_sec = 0;
		t.tv_usec =pthis->deadlock_detect_val;
		ret=dbenv->lock_detect(dbenv, 0, DB_LOCK_YOUNGEST, NULL);
		if (ret!=0)
		{
			fprintf(stderr,"detect deadlock: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
		(void)select(0, NULL, NULL, NULL, &t);
	}
	fprintf(stderr, "db deadlock detect thread quit\n");
	return (NULL);
}
