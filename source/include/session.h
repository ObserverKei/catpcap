#ifndef __SESSION_H__
#define __SESSION_H__

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus


#include <stdint.h>

typedef union addr_ip_st{
	uint32_t addr_ip;
	uint8_t ipv4_all[4];
} addr_ip_t;

typedef struct l3_addr_st {
	union {
//#define addr_ip  ip.ipv4[3]		//防止把使用者的同名变量替换，先注释掉
#define addr_ip6 ipv6				//ipv6
#define addr_all ipv6               //成员
		uint32_t addr_ip;
		uint32_t ipv6[4];
	};
} l3_addr_t;

#define SESSION_TRANSPORT_TCP		10 
#define SESSION_TRANSPORT_UDP		11 
#define SESSION_TRANSPORT_ICMP		12 
#define SESSION_NETWORK_IPV4		13 
#define SESSION_NETWORK_IPV6		14
#define SESSION_APPLICATION_UNKNOW	0
#define SESSION_APPLICATION_HTTP	101
#define SESSION_SKBDIR_UNKNOW		0
#define SESSION_SKBDIR_TO_SERVER	1
#define SESSION_SKBDIR_TO_CLIENT	2
#define SESSION_PACK_CONTINUE		0

#define NIPQUAD(addr) \
	((const unsigned char *)&addr)[0], \
	((const unsigned char *)&addr)[1], \
	((const unsigned char *)&addr)[2], \
	((const unsigned char *)&addr)[3]

typedef struct session_st {
	void *hander;				//用户委托数据
	l3_addr_t src_ip;			//源ip
	l3_addr_t dst_ip;			//目的ip
	uint16_t src_port;			//源端口
	uint16_t dst_port;			//目的端口
	uint16_t transport;			//tcp/udp/icmp
	uint16_t network;			//ipv4/ipv6
	uint8_t application;		//http/... 
	uint8_t skbdir;				//数据包方向 skbdir_to_server/skbdir_to_client/skbdir_unknow
	uint64_t pks;				//当前处理的是这个文件的第几个数据包
} session_t;


#ifdef __cplusplus
}
#endif//__cplusplus

#endif//__SESSION_H__
