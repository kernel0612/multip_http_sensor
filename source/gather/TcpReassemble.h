/*
 * TcpReassemble.h
 *
 *  Created on: 2014Äê8ÔÂ6ÈÕ
 *      Author: Administrator
 */

#ifndef TCPREASSEMBLE_H_
#define TCPREASSEMBLE_H_
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <config.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING			/* now a valid state */
};
#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8

# define NIDS_JUST_EST 1
# define NIDS_DATA 2
# define NIDS_CLOSE 3
# define NIDS_RESET 4
# define NIDS_TIMED_OUT 5
# define NIDS_EXITING   6	/* nids is exiting; last chance to get data */
struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

struct half_stream
{
  char state;
  char collect;
  char collect_urg;

  char *data;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_char wscale_on;
  u_int curr_ts;
  u_int wscale;
  struct skbuff *list;
  struct skbuff *listtail;
};

struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  void *user;
};
struct tcp_timeout
{
  struct tcp_stream *a_tcp;
  struct timeval timeout;
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};
struct skbuff {
  struct skbuff *next;
  struct skbuff *prev;

  void *data;
  u_int len;
  u_int truesize;
  u_int urg_ptr;

  char fin;
  char urg;
  u_int seq;
  u_int ack;
};
struct proc_node {
  void (*item)();
  struct proc_node *next;
};

struct lurker_node {
  void (*item)();
  void *data;
  char whatto;
  struct lurker_node *next;
};

char * test_malloc(int x);
#define mknew(x)	(x *)test_malloc(sizeof(x))
#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)
class TcpReassemble {
public:
	TcpReassemble();
	virtual ~TcpReassemble();

	int init(int size=1040);
	int fini();
	int register_tcp_callback(void (*x));
	int process(u_char* data,int skblen,tcp_stream** outstream,void** data);

private:

	//hash field
	void init_hash();
	void getrnd();
	u_int mkhash (u_int src , u_short sport, u_int dest, u_short dport);
    int mk_hash_index(struct tuple4 addr);
	//end of hash field

	//stream field
	struct tcp_stream *find_stream(struct tcphdr * this_tcphdr, struct ip * this_iphdr,
		    int *from_client);
	struct tcp_stream* nids_find_tcp_stream(struct tuple4 *addr);
	void nids_free_tcp_stream(struct tcp_stream * a_tcp);
	void add_new_tcp(struct tcphdr * this_tcphdr, struct ip * this_iphdr);
	int get_ts(struct tcphdr * this_tcphdr, unsigned int * ts);
	int get_wscale(struct tcphdr * this_tcphdr, unsigned int * ws);
	void del_tcp_closing_timeout(struct tcp_stream * a_tcp);
	void purge_queue(struct half_stream * h);
	//end of stream field

	//seq field
	inline int before(u_int seq1, u_int seq2){
	  return ((int)(seq1 - seq2) < 0);
	}

	inline int after(u_int seq1, u_int seq2){
	  return ((int)(seq2 - seq1) < 0);
	}
	//end of seq field

	//queue field

	void handle_ack(struct half_stream * snd, u_int acknum);
	void prune_queue(struct half_stream * rcv, struct tcphdr * this_tcphdr);
	void tcp_queue(struct tcp_stream * a_tcp, struct tcphdr * this_tcphdr,
		  struct half_stream * snd, struct half_stream * rcv,
		  char *data, int datalen, int skblen
		  );
    void add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
		     struct half_stream * snd,
		     u_char *data, int datalen,
		     u_int this_seq, char fin, char urg, u_int urg_ptr);
    void add2buf(struct half_stream * rcv, char *data, int datalen);
    void add_tcp_closing_timeout(struct tcp_stream * a_tcp);
	//end of queue field
private:
	struct tcp_stream **tcp_stream_table;
	struct tcp_stream *streams_pool;
	int tcp_stream_table_size;
	int max_stream;
	struct tcp_stream* free_streams;
	struct tcp_timeout* nids_tcp_timeouts;
	struct tcp_stream* tcp_latest;
	struct tcp_stream* tcp_oldest;
	struct tcp_stream *free_streams;
	struct proc_node *tcp_procs;
	int tcp_num ;
	//hash field
	u_char _perm[12];
	u_char _xor[12];
	//end of hash field
};

#endif /* TCPREASSEMBLE_H_ */
