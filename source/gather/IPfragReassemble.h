/*
 * IPfragReassemble.h
 *
 *  Created on: 2014Äê8ÔÂ7ÈÕ
 *      Author: Administrator
 */

#ifndef IPFRAGREASSEMBLE_H_
#define IPFRAGREASSEMBLE_H_
#include <config.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define IP_CE		0x8000	/* Flag: "Congestion" */
#define IP_DF		0x4000	/* Flag: "Don't Fragment" */
#define IP_MF		0x2000	/* Flag: "More Fragments" */
#define IP_OFFSET	0x1FFF	/* "Fragment Offset" part */

#define IPF_NOTF 1
#define IPF_NEW  2
#define IPF_ISF  3

#define IPFRAG_HIGH_THRESH		(256*1024)
#define IPFRAG_LOW_THRESH		(192*1024)
#define IP_FRAG_TIME	(30 * 1000)	/* fragment lifetime */

#define mknew(x)	(x *)test_malloc(sizeof(x))
#define UNUSED 314159
#define FREE_READ UNUSED
#define FREE_WRITE UNUSED
#define GFP_ATOMIC UNUSED
struct sk_buff {
  char *data;
  int truesize;
};

struct hostfrags {
  struct ipq *ipqueue;
  int ip_frag_mem;
  u_int ip;
  int hash_index;
  struct hostfrags *prev;
  struct hostfrags *next;
};

/* Describe an IP fragment. */
struct ipfrag {
  int offset;			/* offset of fragment in IP datagram    */
  int end;			/* last byte of data in datagram        */
  int len;			/* length of this fragment              */
  struct sk_buff *skb;		/* complete received fragment           */
  unsigned char *ptr;		/* pointer into real fragment data      */
  struct ipfrag *next;		/* linked list pointers                 */
  struct ipfrag *prev;
};

/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq {
  unsigned char *mac;		/* pointer to MAC header                */
  struct ip *iph;		/* pointer to IP header                 */
  int len;			/* total length of original datagram    */
  short ihlen;			/* length of the IP header              */
  short maclen;			/* length of the MAC header             */
  struct timer_list timer;	/* when will this queue expire?         */
  struct ipfrag *fragments;	/* linked list of received fragments    */
  struct hostfrags *hf;
  struct ipq *next;		/* linked list pointers                 */
  struct ipq *prev;
  // struct device *dev;	/* Device - for icmp replies */
};
struct timer_list {
  struct timer_list *prev;
  struct timer_list *next;
  int expires;
  void (*function)();
  unsigned long data;
  // struct ipq *frags;
};
class IPfragReassemble {
public:
	IPfragReassemble();
	virtual ~IPfragReassemble();


	int init(int);
	int fini();
	int process(struct ip *, struct ip **);


private:
	int ip_defrag_stub(struct ip *iph, struct ip **defrag);
	char * ip_defrag(struct ip *iph, struct sk_buff *skb);
	int hostfrag_find(struct ip * iph);
	int frag_index(struct ip * iph);
	int ip_done(struct ipq * qp);
	char *ip_glue(struct ipq * qp);
	void ip_free(struct ipq * qp);
	struct ipq *ip_find(struct ip * iph);
	struct ipq *ip_create(struct ip * iph);
	void ip_expire(unsigned long arg);
	void ip_evictor(void);
	int jiffies();
	void atomic_sub(int ile, int *co);
	void atomic_add(int ile, int *co);
	void kfree_skb(struct sk_buff * skb, int type);
	void panic(char *str);
	void add_timer(struct timer_list * x);
	void del_timer(struct timer_list * x);
	void frag_kfree_skb(struct sk_buff * skb, int type);
	void frag_kfree_s(void *ptr, int len);
	void *frag_kmalloc(int size, int dummy);
	void hostfrag_create(struct ip * iph);
	struct ipfrag *ip_frag_create(int offset, int end, struct sk_buff * skb, unsigned char *ptr);
	void rmthis_host();
private:
	struct hostfrags **fragtable;
	struct hostfrags *this_host;
	int hash_size;
	unsigned int time0;
	int numpack ;
	struct timer_list *timer_head , *timer_tail;
    int timenow;
};

#endif /* IPFRAGREASSEMBLE_H_ */
