#ifndef  COMMONDEF_H
#define  COMMONDEF_H
#include <stdint.h>
#define  MAX_BUFF_SIZE             65535
#define  COOKIE_BUF_SIZE           4096
#define  URL_BUF_SIZE              4096
#define  METHOD_BUF_SIZE          32
#define  REQUEST_CONTENT_BUF_SIZE 1024
#define  HOST_BUF_SIZE             64
#define  DES_BUF_SIZE             32
#define  SRC_BUF_SIZE              32
#define  HTTPTYPE_BUFF_SIZE        16
#define  REFERER_BUF_SIZE          4096
#define  USERAGENT_BUF_SIZE        512
#define  ACCEPT_BUF_SIZE          128
#define  ACCEPTENCODE_BUF_SIZE     128
#define  REQUESTID_BUF_SIZE        64

#define  CONTENTTYPE_BUF_SIZE      64
#define  RESPONSECODE_BUF_SIZE     64
#define  RESPONSEID_BUF_SIZE       64
#define  DATE_BUF_SIZE             32
#define  CAP_CONTENT_BLOCK_SIZE     512

#define  PARSE_CONTENT_THREAD_NUM    5
struct serverInfo 
{
	char cookie[COOKIE_BUF_SIZE];
	char url[URL_BUF_SIZE];
	char method[METHOD_BUF_SIZE];
	char content[REQUEST_CONTENT_BUF_SIZE];  //请求正文 只取1024字节
	char host[HOST_BUF_SIZE];
	char des[DES_BUF_SIZE];
	char src[SRC_BUF_SIZE];
	char httpType[HTTPTYPE_BUFF_SIZE];
	char refer[REFERER_BUF_SIZE];
	char userAgent[USERAGENT_BUF_SIZE];
	char accept[ACCEPT_BUF_SIZE];
	char accEncod[ACCEPTENCODE_BUF_SIZE];
	unsigned short desPort;
	unsigned short srcPort;
	char timeStamp[64];    //时间戳
	unsigned int cntSize;
	char requestID[REQUESTID_BUF_SIZE];    //uuid
};
struct clientInfo
{ 
	char contentType[CONTENTTYPE_BUF_SIZE];
	char resCode[RESPONSECODE_BUF_SIZE];
	char requestID[REQUESTID_BUF_SIZE];  //uuid
	char responseID[RESPONSEID_BUF_SIZE];  //uuid
	char date[DATE_BUF_SIZE];
	char* content;      //响应 正文  动态申请
	int complete;
	int isChunked;
	int isFilter;
	unsigned short srcPort;
	unsigned int contentSize;
	unsigned int currentSize;
	unsigned int lackChunkedSize;
};
typedef enum 
{
	INTERACTION_NORMAL=1,
	INTERACTION_TIMEOUT,
	INTERACTION_RESET,
	INTERACTION_CLOSE
}interaction_status;
//struct oneInteraction
//{
//	struct serverInfo* server;
//	struct clientInfo* client;
//	interaction_status status;
//};
typedef enum
{
	CLIENT_CNT=1,
	SERVER_CNT
}CntType;
struct CapContent               //捕获的两端内容
{
	char srvCnt[MAX_BUFF_SIZE];      
	char cliCnt[MAX_BUFF_SIZE];
	unsigned int srvCntSize;
	unsigned int cliCntSize;
	char srvSrc[32];
	char srvDes[32];
	char cliSrc[32];
	char cliDes[32];
	unsigned short srvSport;
	unsigned short srvDport;
	unsigned short cliSport;
	unsigned short cliDport;   
	unsigned short srvHasCnt;
	unsigned short cliHasCnt;
};
struct cap_content_block
{
	char CntBlock[CAP_CONTENT_BLOCK_SIZE+1];   
	unsigned int CntBlockSize;
	char Src[32];
	char Des[32];
	unsigned short Sport;
	unsigned short Dport;   
	CntType   type;
	unsigned short CurrBlockNum;
	unsigned short TotalBlockNum;
};

struct RequestInfo
{
	char requestID[REQUESTID_BUF_SIZE];    //uuid
	char timeStamp[64];    //时间戳
	uint32_t sip;
	uint16_t sport;
	uint32_t dip;
	uint16_t dport;
	char requestMethod[METHOD_BUF_SIZE];
	char url[URL_BUF_SIZE];
	char httpProtoType[HTTPTYPE_BUFF_SIZE];
	char referer[REFERER_BUF_SIZE];
	char postContent[REQUEST_CONTENT_BUF_SIZE];
	char cookie[COOKIE_BUF_SIZE];
	char accept[ACCEPT_BUF_SIZE];
	char acceptEncoding[ACCEPTENCODE_BUF_SIZE];
	char userAgent[USERAGENT_BUF_SIZE];
	char host[HOST_BUF_SIZE];
	char connection[1024];
	char loginAccount[64];
	char ipAddress[64];       //来源地市
	char ipBusiness[64];   //来源部门
	char resName[64];
	char resCode[128];
	uint32_t resID;
	//uint32_t contentFlag;
};

struct ResponseInfo
{
	char responseID[RESPONSEID_BUF_SIZE];  //uuid
	char requestID[REQUESTID_BUF_SIZE];  //uuid
	char timeStamp[64];    //时间戳
	char contentType[CONTENTTYPE_BUF_SIZE];
	char resCode[RESPONSECODE_BUF_SIZE];
	uint32_t pageSize;
	char pageContent[1024];
	char pageTittle[1024];
};
struct InteractionInfo{
	RequestInfo*  request;
	ResponseInfo* response;
	uint16_t status;
};

struct nms_app_obj{
	   char app_uuid[128];
	   char app_name[128];
	   char app_code[128];
	   char parent_id[128];
	   char level[128];
	   char app_ip[128];
	   char app_port[128];
	   char app_protocol[128];
	   char app_url[500];
	   char app_status[128];
};
struct nms_ipaddress{
	   char ipaddress_uuid[128];
	   char ip_start[128];
	   char ip_end[128];
	   char ip_address[64];
	   char ip_business[64];
	   char ip_start_value[38];
	   char ip_end_value[38];
};
struct nms_account_rule{
	   char accrule_uuid[128];
	   char app_uuid[128];
	   char server_ip[500];
	   char domain_ip[128];
	   char page_url[128];
	   char param_get[500];
	   char param_post[500];
	   char cookie[500];
	   char domain_mode[16];
	   char url_mode[16];
	   char rule_content[2000];
};

#endif
