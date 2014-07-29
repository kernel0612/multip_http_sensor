#ifndef MY_BERKELEYDBBASEDFIFO_H
#define MY_BERKELEYDBBASEDFIFO_H
#include "my_fifo.h"
#include "my_berkeleyDB.h"
#define  BERKELEY_FIFO_SIZE   1024*1024*10
template<typename T>
class my_berkeleyDBbased_fifo :
	public my_fifo<T>
{
public:
	my_berkeleyDBbased_fifo(unsigned long size=BERKELEY_FIFO_SIZE);
public:
	~my_berkeleyDBbased_fifo(void);

	virtual int init();
	virtual int push_back(T content);
	virtual int pop_front(T& content);

	int disabled();
	int enabled();

    int set_db_name(const char* name);
private:
	my_berkeleyDB  _db;
	char key[16];
	typedef enum
	{
		ENABLED,
		DISABLED
	}STATUS;
	STATUS _status;

	char _db_name[64];
};
template<typename T>
my_berkeleyDBbased_fifo<T>::my_berkeleyDBbased_fifo(unsigned long size):my_fifo<T>(size),_status(ENABLED)
{
	memset(_db_name,0,64);
}
template<typename T>
my_berkeleyDBbased_fifo<T>::~my_berkeleyDBbased_fifo(void)
{
}
template<typename T>
int my_berkeleyDBbased_fifo<T>::init()
{
	return _db.open(_db_name,DB_QUEUE);
}
template<typename T>
int my_berkeleyDBbased_fifo<T>::push_back(T content)
{	
	//ACE_Time_Value time_out_v=ACE_Time_Value(5)+ACE_OS::gettimeofday();
//    int ret=0;
//	my_ace_guard guard(this->mutex);	
	//ACE_Guard<ACE_Recursive_Thread_Mutex> guard(this->mutex);
//	while(this->is_full()==0)
//	{
//		ret=this->condNotfull.wait(/*&time_out_v*/);
//		if (ret==-1)
//		{
//			return 1;
//		}
//		if (this->_status==this->DISABLED)
//		{
//			return 1;
//		}
//	}
	if (this->_status==this->DISABLED)
	{
		return 1;
	}
//	if (_db.put(&content,sizeof(T))==0)
//	{
//		this->tail=(this->tail+1)%this->maxSize;
//		if (this->tail==this->head)
//		{
//			this->full=1;
//		}
//        this->condNotempty.signal();
//		return 0;
//	}
//	return -1;
	return _db.put(&content,sizeof(T));
}
template<typename T>
int my_berkeleyDBbased_fifo<T>::pop_front(T& content)
{
	//ACE_Time_Value time_out_v=ACE_Time_Value(5)+ACE_OS::gettimeofday();
	T* p=0;
	int size=0;
	int ret=0;
//	my_ace_guard guard(this->mutex);
//	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(this->mutex);
//	while(this->is_empty()==0)
//	{
//		ret=this->condNotempty.wait(/*&time_out_v*/);
//		if (ret==-1)
//		{
//			return 1;
//		}
//		if (this->_status==this->DISABLED)
//		{
//			return 1;
//		}
//	}
	if (this->_status==this->DISABLED)
	{
		return 1;
	}
//	if (_db.get((void**)&p,&size)==0)
//	{
//		content=*p;
//		this->head=(this->head+1)%this->maxSize;
//		if (this->head==this->tail)
//		{
//			this->full=0;
//		}
//		this->condNotfull.signal();
//		return 0;
//	}
    if(_db.get((void**)&p,&size)==0){
    	content=*p;
    	return 0;
    }
    return -1;
}
template<typename T>
int my_berkeleyDBbased_fifo<T>::disabled()
{
	//my_ace_guard guard(this->mutex);
	//ACE_Guard<ACE_Recursive_Thread_Mutex> guard(this->mutex);
	this->_status=this->DISABLED;
	//this->condNotempty.broadcast();
	//this->condNotfull.broadcast();
	return 0;
}
template<typename T>
int my_berkeleyDBbased_fifo<T>::enabled()
{
	//my_ace_guard guard(this->mutex);
	//ACE_Guard<ACE_Recursive_Thread_Mutex> guard(this->mutex);
	this->_status=this->ENABLED;
	return 0;
}
template<typename T>
int my_berkeleyDBbased_fifo<T>::set_db_name(const char* name){
	if(!name){
		return -1;
	}
	memcpy(_db_name,name,63);
	return 0;
}
#endif
