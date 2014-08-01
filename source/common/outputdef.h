#ifndef OUTPUTDEF_H
#define OUTPUTDEF_H
#define  GET_REGEX_CONTENT_SIZE    512
struct outputSerInfo
{
	char cookie[4096];
	char url[4096];
	char method[1024];
	char content[GET_REGEX_CONTENT_SIZE];  //ʶ�������
	char host[64];
	char des[32];
	char src[32];
	char httpType[16];
	char refer[4096];
	char userAgent[512];
	char accept[128];
	char accEncod[128];
	char timeStamp[64];    //ʱ���
	char requestID[64];    //uuid   ��Ϊkey
	unsigned short desPort;
	unsigned short srcPort;
};

struct outputCliInfo
{
	char contentType[64];
	char resCode[64];
	char requestID[64];  //uuid  ��Ϊkey
	char responseID[64];  //uuid   ��Ϊkey
	char date[32];
	char content[GET_REGEX_CONTENT_SIZE];      //ʶ������� 
};

#endif