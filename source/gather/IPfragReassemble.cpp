/*
 * IPfragReassemble.cpp
 *
 *  Created on: 2014年8月7日
 *      Author: Administrator
 */

#include "IPfragReassemble.h"

IPfragReassemble::IPfragReassemble() {
	// TODO Auto-generated constructor stub
	fragtable=0;
	this_host=0;
	hash_size=0;
	time0=0;
	numpack=0;
	timer_head=0;
	timer_tail=0;
	timenow=0;
}

IPfragReassemble::~IPfragReassemble() {
	// TODO Auto-generated destructor stub
}
char *test_malloc(int x){
	  char *ret = malloc(x);

	  if (!ret){
		    //nids_params.no_mem("test_malloc");
	  }
	  return ret;
}

int IPfragReassemble::jiffies()
{
  struct timeval tv;

  if (timenow)
    return timenow;
  gettimeofday(&tv, 0);
  timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;

  return timenow;
}

/* Memory Tracking Functions */
void IPfragReassemble::atomic_sub(int ile, int *co)
{
  *co -= ile;
}

void IPfragReassemble::atomic_add(int ile, int *co)
{
  *co += ile;
}

void IPfragReassemble::kfree_skb(struct sk_buff * skb, int type)
{
  (void)type;
  free(skb);
}

void IPfragReassemble::panic(char *str)
{
  fprintf(stderr, "%s", str);
  exit(1);
}

void IPfragReassemble::add_timer(struct timer_list * x)
{
  if (timer_tail) {
    timer_tail->next = x;
    x->prev = timer_tail;
    x->next = 0;
    timer_tail = x;
  }
  else {
    x->prev = 0;
    x->next = 0;
    timer_tail = timer_head = x;
  }
}

void IPfragReassemble::del_timer(struct timer_list * x)
{
  if (x->prev)
    x->prev->next = x->next;
  else
    timer_head = x->next;
  if (x->next)
    x->next->prev = x->prev;
  else
    timer_tail = x->prev;
}

void IPfragReassemble::frag_kfree_skb(struct sk_buff * skb, int type)
{
  if (this_host)
    atomic_sub(skb->truesize, &this_host->ip_frag_mem);
  kfree_skb(skb, type);
}

void IPfragReassemble::frag_kfree_s(void *ptr, int len)
{
  if (this_host)
    atomic_sub(len, &this_host->ip_frag_mem);
  free(ptr);
}

void *IPfragReassemble::frag_kmalloc(int size, int dummy)
{
  void *vp = (void *) malloc(size);
  (void)dummy;
  if (!vp)
    return NULL;
  atomic_add(size, &this_host->ip_frag_mem);

  return vp;
}

int IPfragReassemble::init(int n){
	  struct timeval tv;

	  gettimeofday(&tv, 0);
	  time0 = tv.tv_sec;
	  fragtable = (struct hostfrags **) calloc(n, sizeof(struct hostfrags *));
	  if (!fragtable){
		   //nids_params.no_mem("ip_frag_init");
	  }

	  hash_size = n;
	return 0;
}
int IPfragReassemble::fini(){
	  if (fragtable) {
	    free(fragtable);
	    fragtable = NULL;
	  }
	return 0;
}
int IPfragReassemble::process(struct ip *iph, struct ip **defrag){

	return ip_defrag_stub(iph,defrag);
}

int IPfragReassemble::ip_defrag_stub(struct ip *iph, struct ip **defrag){
  int offset, flags, tot_len;
  struct sk_buff *skb;

  numpack++;
  timenow = 0;
  while (timer_head && timer_head->expires < jiffies()) {
    this_host = ((struct ipq *) (timer_head->data))->hf;
    timer_head->function(timer_head->data);                        //timeout function
  }
  offset = ntohs(iph->ip_off);
  flags = offset & ~IP_OFFSET;
  offset &= IP_OFFSET;
  if (((flags & IP_MF) == 0) && (offset == 0)) {
    ip_defrag(iph, 0);
    return IPF_NOTF;
  }
  tot_len = ntohs(iph->ip_len);
  skb = (struct sk_buff *) malloc(tot_len + sizeof(struct sk_buff));
  if (!skb){
	 // nids_params.no_mem("ip_defrag_stub");
  }

  skb->data = (char *) (skb + 1);
  memcpy(skb->data, iph, tot_len);
  skb->truesize = tot_len + 16 + nids_params.dev_addon;        //?
  skb->truesize = (skb->truesize + 15) & ~15;
  skb->truesize += nids_params.sk_buff_size;                   //?

  if ((*defrag = (struct ip *)ip_defrag((struct ip *) (skb->data), skb)))   //集齐了分片
    return IPF_NEW;    //返回合并后龅ip包

  return IPF_ISF;
}


char * IPfragReassemble::ip_defrag(struct ip *iph, struct sk_buff *skb){       //处理ip分片的主要逻辑
  struct ipfrag *prev, *next, *tmp;
  struct ipfrag *tfp;
  struct ipq *qp;
  char *skb2;
  unsigned char *ptr;
  int flags, offset;
  int i, ihl, end;
if (!hostfrag_find(iph) && skb)
   hostfrag_create(iph);

 /* Start by cleaning up the memory. */
 if (this_host)
   if (this_host->ip_frag_mem > IPFRAG_HIGH_THRESH)   //内存占用过多 释放
     ip_evictor();

 /* Find the entry of this IP datagram in the "incomplete datagrams" queue. */
 if (this_host)
   qp = ip_find(iph);
 else
   qp = 0;

 /* Is this a non-fragmented datagram? */
 offset = ntohs(iph->ip_off);
 flags = offset & ~IP_OFFSET;
 offset &= IP_OFFSET;
 if (((flags & IP_MF) == 0) && (offset == 0)) {
   if (qp != NULL)
     ip_free(qp);		/* Fragmented frame replaced by full
				   unfragmented copy */
   return 0;
 }

 /* ip_evictor() could have removed all queues for the current host */
 if (!this_host)
   hostfrag_create(iph);

 offset <<= 3;			/* offset is in 8-byte chunks */
 ihl = iph->ip_hl * 4;

 /*
   If the queue already existed, keep restarting its timer as long as
   we still are receiving fragments.  Otherwise, create a fresh queue
   entry.
 */
 if (qp != NULL) {
   /* ANK. If the first fragment is received, we should remember the correct
      IP header (with options) */
   if (offset == 0) {
     qp->ihlen = ihl;
     memcpy(qp->iph, iph, ihl + 8);
   }
   del_timer(&qp->timer);
   qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds */
   qp->timer.data = (unsigned long) qp;	/* pointer to queue */
   qp->timer.function = ip_expire;	/* expire function */
   add_timer(&qp->timer);
 }
 else {
   /* If we failed to create it, then discard the frame. */
   if ((qp = ip_create(iph)) == NULL) {
     kfree_skb(skb, FREE_READ);
     return NULL;
   }
 }
 /* Attempt to construct an oversize packet. */
 if (ntohs(iph->ip_len) + (int) offset > 65535) {
   // NETDEBUG(printk("Oversized packet received from %s\n", int_ntoa(iph->ip_src.s_addr)));
   //nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, iph, 0);
   kfree_skb(skb, FREE_READ);
   return NULL;
 }
 /* Determine the position of this fragment. */
 end = offset + ntohs(iph->ip_len) - ihl;

 /* Point into the IP datagram 'data' part. */
 ptr = (unsigned char *)(skb->data + ihl);

 /* Is this the final fragment? */
 if ((flags & IP_MF) == 0)
   qp->len = end;

 /*
   Find out which fragments are in front and at the back of us in the
   chain of fragments so far.  We must know where to put this
   fragment, right?
 */
 prev = NULL;
 for (next = qp->fragments; next != NULL; next = next->next) {
   if (next->offset >= offset)
     break;			/* bingo! */
   prev = next;
 }
 /*
   We found where to put this one.  Check for overlap with preceding
   fragment, and, if needed, align things so that any overlaps are
   eliminated.
 */
 if (prev != NULL && offset < prev->end) {
   // nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);
   i = prev->end - offset;
   offset += i;		/* ptr into datagram */
   ptr += i;			/* ptr into fragment data */
 }
 /*
   Look for overlap with succeeding segments.
   If we can merge fragments, do it.
 */
 for (tmp = next; tmp != NULL; tmp = tfp) {
   tfp = tmp->next;
   if (tmp->offset >= end)
     break;			/* no overlaps at all */
   //nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);

   i = end - next->offset;	/* overlap is 'i' bytes */
   tmp->len -= i;		/* so reduce size of    */
   tmp->offset += i;		/* next fragment        */
   tmp->ptr += i;
   /*
     If we get a frag size of <= 0, remove it and the packet that it
     goes with. We never throw the new frag away, so the frag being
     dumped has always been charged for.
   */
   if (tmp->len <= 0) {
     if (tmp->prev != NULL)
	tmp->prev->next = tmp->next;
     else
	qp->fragments = tmp->next;

     if (tmp->next != NULL)
	tmp->next->prev = tmp->prev;

     next = tfp;		/* We have killed the original next frame */

     frag_kfree_skb(tmp->skb, FREE_READ);
     frag_kfree_s(tmp, sizeof(struct ipfrag));
   }
 }
 /* Insert this fragment in the chain of fragments. */
 tfp = NULL;
 tfp = ip_frag_create(offset, end, skb, ptr);

 /*
   No memory to save the fragment - so throw the lot. If we failed
   the frag_create we haven't charged the queue.
 */
 if (!tfp) {
  // nids_params.no_mem("ip_defrag");
   kfree_skb(skb, FREE_READ);
   return NULL;
 }
 /* From now on our buffer is charged to the queues. */
 tfp->prev = prev;
 tfp->next = next;
 if (prev != NULL)
   prev->next = tfp;
 else
   qp->fragments = tfp;

 if (next != NULL)
   next->prev = tfp;

 /*
   OK, so we inserted this new fragment into the chain.  Check if we
   now have a full IP datagram which we can bump up to the IP
   layer...
 */
 if (ip_done(qp)) {
   skb2 = ip_glue(qp);		/* glue together the fragments */
   return (skb2);
 }
 return (NULL);
}
int IPfragReassemble::frag_index(struct ip * iph){
  unsigned int ip = ntohl(iph->ip_dst.s_addr);

  return (ip % hash_size);
}
int IPfragReassemble::hostfrag_find(struct ip * iph){
  int hash_index = frag_index(iph);
  struct hostfrags *hf;

  this_host = 0;
  for (hf = fragtable[hash_index]; hf; hf = hf->next)
    if (hf->ip == iph->ip_dst.s_addr) {
      this_host = hf;
      break;
    }
  if (!this_host)
    return 0;
  else
    return 1;
}
int IPfragReassemble::ip_done(struct ipq * qp){
  struct ipfrag *fp;
  int offset;

  /* Only possible if we received the final fragment. */
  if (qp->len == 0)
    return (0);

  /* Check all fragment offsets to see if they connect. */
  fp = qp->fragments;
  offset = 0;
  while (fp != NULL) {
    if (fp->offset > offset)                   //should equal
      return (0);		/* fragment(s) missing */
    offset = fp->end;
    fp = fp->next;
  }
  /* All fragments are present. */
  return (1);
}
char *IPfragReassemble::ip_glue(struct ipq * qp){
  char *skb;
  struct ip *iph;
  struct ipfrag *fp;
  unsigned char *ptr;
  int count, len;

  /* Allocate a new buffer for the datagram. */
  len = qp->ihlen + qp->len;

  if (len > 65535) {
    // NETDEBUG(printk("Oversized IP packet from %s.\n", int_ntoa(qp->iph->ip_src.s_addr)));
    //nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, qp->iph, 0);
    ip_free(qp);
    return NULL;
  }
  if ((skb = (char *) malloc(len)) == NULL) {
    // NETDEBUG(printk("IP: queue_glue: no memory for gluing queue %p\n", qp));
    //nids_params.no_mem("ip_glue");
    ip_free(qp);
    return (NULL);
  }
  /* Fill in the basic details. */
  ptr = (unsigned char *)skb;
  memcpy(ptr, ((unsigned char *) qp->iph), qp->ihlen);
  ptr += qp->ihlen;
  count = 0;

  /* Copy the data portions of all fragments into the new buffer. */
  fp = qp->fragments;
  while (fp != NULL) {
    if (fp->len < 0 || fp->offset + qp->ihlen + fp->len > len) {
      //NETDEBUG(printk("Invalid fragment list: Fragment over size.\n"));
      //nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_INVLIST, qp->iph, 0);
      ip_free(qp);
      //kfree_skb(skb, FREE_WRITE);
      //ip_statistics.IpReasmFails++;
      free(skb);
      return NULL;
    }
    memcpy((ptr + fp->offset), fp->ptr, fp->len);
    count += fp->len;
    fp = fp->next;
  }
  /* We glued together all fragments, so remove the queue entry. */
  ip_free(qp);

  /* Done with all fragments. Fixup the new IP header. */
  iph = (struct ip *) skb;
  iph->ip_off = 0;
  iph->ip_len = htons((iph->ip_hl * 4) + count);
  // skb->ip_hdr = iph;

  return (skb);
}
void IPfragReassemble::ip_free(struct ipq * qp){
  struct ipfrag *fp;
  struct ipfrag *xp;

  /* Stop the timer for this entry. */
  del_timer(&qp->timer);

  /* Remove this entry from the "incomplete datagrams" queue. */
  if (qp->prev == NULL) {
    this_host->ipqueue = qp->next;
    if (this_host->ipqueue != NULL)
      this_host->ipqueue->prev = NULL;
    else
      rmthis_host();
  }
  else {
    qp->prev->next = qp->next;
    if (qp->next != NULL)
      qp->next->prev = qp->prev;
  }
  /* Release all fragment data. */
  fp = qp->fragments;
  while (fp != NULL) {
    xp = fp->next;
    frag_kfree_skb(fp->skb, FREE_READ);
    frag_kfree_s(fp, sizeof(struct ipfrag));
    fp = xp;
  }
  /* Release the IP header. */
  frag_kfree_s(qp->iph, 64 + 8);

  /* Finally, release the queue descriptor itself. */
  frag_kfree_s(qp, sizeof(struct ipq));
}
struct ipq *IPfragReassemble::ip_find(struct ip * iph){
  struct ipq *qp;
  struct ipq *qplast;

  qplast = NULL;
  for (qp = this_host->ipqueue; qp != NULL; qplast = qp, qp = qp->next) {
    if (iph->ip_id == qp->iph->ip_id &&
	iph->ip_src.s_addr == qp->iph->ip_src.s_addr &&
	iph->ip_dst.s_addr == qp->iph->ip_dst.s_addr &&
	iph->ip_p == qp->iph->ip_p) {
      del_timer(&qp->timer);	/* So it doesn't vanish on us. The timer will
				   be reset anyway */
      return (qp);
    }
  }
  return (NULL);
}
struct ipq *IPfragReassemble::ip_create(struct ip * iph){
  struct ipq *qp;
  int ihlen;

  qp = (struct ipq *) frag_kmalloc(sizeof(struct ipq), GFP_ATOMIC);
  if (qp == NULL) {
    // NETDEBUG(printk("IP: create: no memory left !\n"));
   // nids_params.no_mem("ip_create");
    return (NULL);
  }
  memset(qp, 0, sizeof(struct ipq));

  /* Allocate memory for the IP header (plus 8 octets for ICMP). */
  ihlen = iph->ip_hl * 4;
  qp->iph = (struct ip *) frag_kmalloc(64 + 8, GFP_ATOMIC);
  if (qp->iph == NULL) {
    //NETDEBUG(printk("IP: create: no memory left !\n"));
    //nids_params.no_mem("ip_create");
    frag_kfree_s(qp, sizeof(struct ipq));
    return (NULL);
  }
  memcpy(qp->iph, iph, ihlen + 8);
  qp->len = 0;
  qp->ihlen = ihlen;
  qp->fragments = NULL;
  qp->hf = this_host;

  /* Start a timer for this entry. */
  qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds     */
  qp->timer.data = (unsigned long) qp;	/* pointer to queue     */
  qp->timer.function = ip_expire;	/* expire function      */
  add_timer(&qp->timer);

  /* Add this entry to the queue. */
  qp->prev = NULL;
  qp->next = this_host->ipqueue;
  if (qp->next != NULL)
    qp->next->prev = qp;
  this_host->ipqueue = qp;

  return (qp);
}

void IPfragReassemble::ip_expire(unsigned long arg){
  struct ipq *qp;

  qp = (struct ipq *) arg;

  /* Nuke the fragment queue. */
  ip_free(qp);
}
void IPfragReassemble::ip_evictor(void){
  // fprintf(stderr, "ip_evict:numpack=%i\n", numpack);
  while (this_host && this_host->ip_frag_mem > IPFRAG_LOW_THRESH) {
    if (!this_host->ipqueue)
      panic("ip_evictor: memcount");
    ip_free(this_host->ipqueue);
  }
}
void IPfragReassemble::hostfrag_create(struct ip * iph)
{
  struct hostfrags *hf = mknew(struct hostfrags);
  int hash_index = frag_index(iph);

  hf->prev = 0;
  hf->next = fragtable[hash_index];
  if (hf->next)
    hf->next->prev = hf;
  fragtable[hash_index] = hf;
  hf->ip = iph->ip_dst.s_addr;
  hf->ipqueue = 0;
  hf->ip_frag_mem = 0;
  hf->hash_index = hash_index;
  this_host = hf;
}
struct ipfrag *IPfragReassemble::ip_frag_create(int offset, int end, struct sk_buff * skb, unsigned char *ptr)
{
  struct ipfrag *fp;

  fp = (struct ipfrag *) frag_kmalloc(sizeof(struct ipfrag), GFP_ATOMIC);
  if (fp == NULL) {
    // NETDEBUG(printk("IP: frag_create: no memory left !\n"));
    //nids_params.no_mem("ip_frag_create");
    return (NULL);
  }
  memset(fp, 0, sizeof(struct ipfrag));

  /* Fill in the structure. */
  fp->offset = offset;
  fp->end = end;
  fp->len = end - offset;
  fp->skb = skb;
  fp->ptr = ptr;

  /* Charge for the SKB as well. */
  this_host->ip_frag_mem += skb->truesize;

  return (fp);
}
void IPfragReassemble::rmthis_host()
{
  int hash_index = this_host->hash_index;

  if (this_host->prev) {
    this_host->prev->next = this_host->next;
    if (this_host->next)
      this_host->next->prev = this_host->prev;
  }
  else {
    fragtable[hash_index] = this_host->next;
    if (this_host->next)
      this_host->next->prev = 0;
  }
  free(this_host);
  this_host = 0;
}
