#ifndef MY_FIFO_H
#define MY_FIFO_H
#include "commondef.h"
//#include "my_ace_guard.h"
//#include "ace/Condition_T.h"
//#include "ace/OS.h"
template<typename T>
class my_fifo
{
public:
	my_fifo(unsigned long size=10);
public:
	virtual ~my_fifo(void);
	virtual int init()=0;
	virtual int push_back(T content)=0;
	virtual int pop_front(T& content)=0;


	virtual int destroy();
	virtual int disabled();
	virtual int enabled();
protected:
	unsigned int get_element_size();
	int is_empty();
	int is_full();
    unsigned int head;
	unsigned int tail;
	int full;
	unsigned long maxSize;
	//ACE_Thread_Mutex  mutex;
	//ACE_Condition<ACE_Thread_Mutex> condNotfull;
	//ACE_Condition<ACE_Thread_Mutex> condNotempty;
	//ACE_Recursive_Thread_Mutex mutex;
	//ACE_Condition<ACE_Recursive_Thread_Mutex> condNotfull;
	//ACE_Condition<ACE_Recursive_Thread_Mutex> condNotempty;
	int quit_flag;

};

template<typename T>
my_fifo<T>::my_fifo(unsigned long size):maxSize(size),full(0),head(0),tail(0)/*,condNotfull(mutex),condNotempty(mutex)*/,quit_flag(0)
{
}
template<typename T>
my_fifo<T>::~my_fifo(void)
{
}
template<typename T>
unsigned int my_fifo<T>::get_element_size()
{
	//my_ace_guard guard(mutex);
	//ACE_Guard<ACE_Recursive_Thread_Mutex> guard(mutex);
	//if (is_full()==0)
	//{
	//	return maxSize;
	//}
	//return (tail-head+1+maxSize)%maxSize;
	return 0;
}

template<typename T>
int my_fifo<T>::is_empty()
{
	if (full==0&&head==tail)
	{
		return 0;
	}
	return -1;
}
template<typename T>
int my_fifo<T>::is_full()
{
	if (full==1&&head==tail)
	{
		return 0;
	}
	return -1;
}
template<typename T>
int my_fifo<T>::destroy()
{
	return -1;
}
template<typename T>
int my_fifo<T>::disabled()
{
	return -1;
}
template<typename T>
int my_fifo<T>::enabled()
{
	return -1;
}
#endif
