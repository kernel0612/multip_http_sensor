#ifndef  COMMONDEF_H
#define  COMMONDEF_H
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
#endif