#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "catpcap.h"
#include "ldapexpr/ldapexpr.h"
#include "ldap.h"

#define catpcap_debug(fmt, ...) do {\
		if (g_catpcap_debug_enable) printf("%s %s (%d) "fmt,__FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);\
	} while (0)

#define MAX_PACKET_LEN		65536

char g_catpcap_debug_enable = 1;

/* pcap头部信息 */
typedef struct pcap_info_st {
	uint32_t magic;				/* 主标识:a1b2c3d4 */
	uint16_t version_major;		/* 主版本号 */
	uint16_t version_minor;		/* 次版本号 */
	uint32_t thiszone;			/* 区域时间0 */
	uint32_t sigfigs;			/* 时间戳0 */
	uint32_t snaplen;			/* 数据包最大长度 */
	uint32_t linktype;			/* 链路层类型 */
} pcap_info_st;

/* pcap每包头部 */
typedef struct packet_head_st {
	uint32_t gmt_sec;			/* 时间戳，秒部分 */
	uint32_t gmt_msec;			/* 时间戳，微秒部分 */
	uint32_t caplen;			/* 被抓取部分的长度 */
	uint32_t len;				/* 数据包原长度 */
} packet_head_st;

/* 二层头，ethhdr，为了避免引入linux/if_ether.h，这里单独定义 */
typedef struct l2_head_st {
	char dest[6];				/* 目的mac地址 */
	char source[6];				/* 源mac地址 */
	uint16_t proto;				/* 三层协议 */
} l2_head_st;

static int print_packet(uint64_t pkti, const l2_head_st *l2h, const struct iphdr *iph, 
						 const struct tcphdr *tcph, const struct udphdr *udph,
						 const char *data, uint16_t ldata, filter_st *filt, p_catpcap_hook_t *hook, void *hander)
{
	if (!iph || (!tcph && !udph)) {
		catpcap_debug("arg fail\n");
		return -1;
	}

	session_t sess = {
		.src_ip.addr_ip = iph->saddr,
		.dst_ip.addr_ip = iph->daddr,
		.src_port = tcph ? tcph->source : udph->source,
		.dst_port = tcph ? tcph->dest : udph->dest,
		.transport = tcph ? SESSION_TRANSPORT_TCP : SESSION_TRANSPORT_UDP, 
		.network = SESSION_NETWORK_IPV4,
		.application = SESSION_APPLICATION_UNKNOW,
		.skbdir = SESSION_SKBDIR_UNKNOW,
		.pks = pkti,
		.hander = hander,
	};
	if (!filt || (filt && !filter_check(filt, (void *)&sess)))
		return hook(hander, &sess, sess.skbdir, data, ldata);
	/* catpcap_debug("%d--\n%s, %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\nuser data len: %d\n", pkti, tcph ? "TCP":"UDP", 
			NIPQUAD(iph->saddr), tcph ? ntohs(tcph->source) : ntohs(udph->source), 
			NIPQUAD(iph->daddr), tcph ? ntohs(tcph->dest) : ntohs(udph->dest), ldata);
	*/
	
	return 0;
}
//packet_idx 为0时，默认遍历整个数据包文件。非0时，从pcap文件的第packet_idx个包开始处理，如果hook返回0，则继续处理下一个包。
int catpcap_file(const char *file_name, FILE *fp, filter_st *filt, p_catpcap_hook_t *hook, void *hander, size_t packet_idx)
{
	if (!file_name){
		catpcap_debug("catpcap_file file_name is NULL\n");
		return -1;
	}
	catpcap_debug("catpcap_file start %s\n", file_name);
	
	pcap_info_st pi;
	if (fread(&pi, sizeof(pi), 1, fp) != 1) {
		perror("Read pcap head");
		goto fail;
	}
	
	if (pi.magic != 0xa1b2c3d4) {
		catpcap_debug("Invalid pcap file magic: %s\n", file_name);
		goto fail;
	}
	
	if (pi.linktype != 1) {
		catpcap_debug("Unsupport pcap linktype(%u): %s\n", pi.linktype, file_name);
		goto fail;
	}
	
	packet_head_st head;
	uint64_t pkt_counter;
	
	for (pkt_counter = 1; fread(&head, sizeof(head), 1, fp) == 1; ++pkt_counter) {		
		if (head.caplen > pi.snaplen || head.caplen > MAX_PACKET_LEN) {
			catpcap_debug("Packet %ld: Invalid packet head(caplen: %u > snaplen: %u)\n",
				pkt_counter, head.caplen, pi.snaplen);
			goto fail;
		}
		
		char data[MAX_PACKET_LEN];
		if (fread(data, 1, head.caplen, fp) != head.caplen) {
			catpcap_debug("Packet %ld: Read packet data failed\n", pkt_counter);
			goto fail;
		}
		
		/* 跳过不需要处理的数据包 */
		if (packet_idx && pkt_counter < packet_idx)
			continue;
		
		char *curr = data;
		l2_head_st *l2hdr = (l2_head_st *)curr;
		curr += sizeof(l2_head_st);
		
		/* 只处理ipv4的包 */
		if (l2hdr->proto != htons(0x800))
			continue;
	
		struct iphdr *iph = (struct iphdr *)curr;
		curr += (iph->ihl * 4);
		
		/* 不处理分片包 */
		if (iph->frag_off & htons(0x3fff))
			continue;
		
		struct tcphdr *tcph = NULL;
		struct udphdr *udph = NULL;
		
		if (iph->protocol == IPPROTO_TCP) {
			tcph = (struct tcphdr *)curr;
			curr += (tcph->doff * 4);
		} else if (iph->protocol == IPPROTO_UDP) {
			udph = (struct udphdr *)curr;
			curr += (sizeof(struct udphdr));
		} else {
			continue;
		}
		
		const char *udata = curr;
		uint16_t ldata = ntohs(iph->tot_len) - (curr - (char *)iph);
		if ((SESSION_PACK_CONTINUE != print_packet(pkt_counter, l2hdr, iph, tcph, udph, udata, ldata, filt, hook, hander)) && packet_idx) 
			return 0;
	}
	
	return 0;
	
fail:
	
	catpcap_debug("exit fail\n");	
	return 1;
}
void catpcap_help(void)
{
	catpcap_debug("demo LDAP pcapfile\n");
	catpcap_debug("\t  LDAP: src_ip\n");
	catpcap_debug("\t  LDAP: dst_ip\n");
	catpcap_debug("\t  LDAP: src_port\n");
	catpcap_debug("\t  LDAP: dst_port\n");
	catpcap_debug("\t  LDAP: transport:\n");
	catpcap_debug("\t  \t=TCP\n");
	catpcap_debug("\t  \t=UDP\n");
}
#define CATPCAP_FILE_MAX 10 /* 最大支持处理文件数量 */
typedef struct catpcap_private_st {
	FILE *fp;
	const char *file_name;
	filter_st *filt;
} catpcap_private_t;
static catpcap_private_t s_catpcap_private[CATPCAP_FILE_MAX] = {0};

int catpcap_init(int file_array_count, char **file_array, const char *policy)
{

	if (!file_array) {//LDAP(policy) 可以为空
		catpcap_debug("file_array is null\n");
		catpcap_help();
		return -1;
	}
	if (file_array_count > CATPCAP_FILE_MAX) {
		catpcap_debug("init fail, file_count:%d > %d \n", file_array_count, CATPCAP_FILE_MAX);
		return -1;
	}
	if (!strcmp("help", file_array[0])) {
		catpcap_help();
		return 0;
	}
	
	int i = 0;
	for (i = 0; (i < file_array_count) && (i < CATPCAP_FILE_MAX); ++i) {
		if (file_array[i]) {
			FILE *fp = fopen(file_array[i], "rb");
			if (!fp) {
				catpcap_debug("file fp is null, try help\n");
				goto init_fail;
			}
			
			filter_st *filt = NULL;
			if (policy) {
				filt = filter_init(policy);
				if (!filt) {
					catpcap_debug("filt is null\n");
					goto init_fail;
				}
				if (0 != ldap_init()) {
					catpcap_debug("ldap fail");
					goto init_fail;
				}
			}
			s_catpcap_private[i].file_name = file_array[i];
			s_catpcap_private[i].fp = fp;
			s_catpcap_private[i].filt = filt;
		} else {
			catpcap_debug("file_array[%d] is null", i);
			goto init_fail;
		}
	}

	return 0;
	
init_fail:
	catpcap_destroy();
	return -1;
}

void catpcap_destroy(void)
{
	int i = 0;
	for (i = 0; i < sizeof(s_catpcap_private)/sizeof(s_catpcap_private[0]); ++i) {
		if (s_catpcap_private[i].fp)
			fclose(s_catpcap_private[i].fp);
		s_catpcap_private[i].fp = NULL;
		if (s_catpcap_private[i].filt)
			filter_destroy(s_catpcap_private[i].filt);
		s_catpcap_private[i].filt = NULL;
		s_catpcap_private[i].file_name = NULL;
	}
}

int catpcap_idx(size_t file_idx, size_t pcaket_idx, p_catpcap_hook_t *hook, void *hander)
{
	if (!hook) {//hander 可以为NULL
		catpcap_debug("hook is null\n");
		catpcap_help();
		return -1;
	}
	int ret = 0;	

	if (s_catpcap_private[file_idx].fp) {//s_catpcap_private[file_idx].filt 未配置策略时可以为NULL
		if (0 != catpcap_file(s_catpcap_private[file_idx].file_name, s_catpcap_private[file_idx].fp, 
				s_catpcap_private[file_idx].filt, hook, hander, pcaket_idx)) {
			ret = -1;
		}
	} 
	
	return ret;

}

int catpcap(p_catpcap_hook_t *hook, void *hander)
{
	catpcap_debug("catpcap start hook(%p) \n", hook);
	if (!hook) {//hander 可以为NULL
		catpcap_debug("hook is null\n");
		catpcap_help();
		return -1;
	}
	int ret = 0;
	
	int i = 0;
	for (i = 0; i < sizeof(s_catpcap_private)/sizeof(s_catpcap_private[0]); ++i) {
		if (s_catpcap_private[i].fp) {//s_catpcap_private[i].filt 未配置策略时可以为NULL
			if (0 != catpcap_file(s_catpcap_private[i].file_name, s_catpcap_private[i].fp, 
					s_catpcap_private[i].filt, hook, hander, 0)) {
				ret = -1;
			}
		} 
	}
	
	return ret;
}

#ifdef	XTEST

#include <assert.h>
#include <errno.h>
#include "xtest.h"

#define MAX_PACKET_COUNT 331

typedef struct hander_st {
	int flag;
} hander_t;

int catpcap_hook(void *hander, session_t *sess, uint8_t dir, const char *data, uint16_t data_len) {
	if (!hander || !data || !sess)
		return -1;
	hander_t *ph = (hander_t *)hander;

	catpcap_debug("-%ld- %s, %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\nuser data len: %d, flag: %d\n", 
			sess->pks, sess->transport == SESSION_TRANSPORT_TCP ? "TCP":"UDP", 
			NIPQUAD(sess->src_ip.addr_ip), ntohs(sess->src_port), 
			NIPQUAD(sess->dst_ip.addr_ip), ntohs(sess->dst_port), data_len, ph->flag);

	if (sess->pks > MAX_PACKET_COUNT)
		return -1;

	return 0;
}

void set_up()
{
	g_catpcap_debug_enable = 0;
}

void tear_down()
{
	g_catpcap_debug_enable = 1;
}

//  完成使用场景的测试
TEST_F(test, init_fail, set_up, tear_down)
{
	char *file[] = {"unittest/1.pcap", "2"};
	assert(0 > catpcap_init(sizeof(file)/sizeof(file[0]), file, NULL));
	catpcap_destroy();
}

//  完成使用场景的测试
TEST_F(test, catpcap_load_sucess, set_up, tear_down)
{
	hander_t flag = { .flag = 1};
	char *file[] = {"unittest/1.pcap"};
	assert(0 == catpcap_init(sizeof(file)/sizeof(file[0]), file, NULL));
	assert(0 == catpcap(catpcap_hook, (void *)&flag));
	catpcap_destroy();
	
	assert(0 == catpcap_init(sizeof(file)/sizeof(file[0]), file, "(src_port=481)"));
	assert(0 == catpcap(catpcap_hook, (void *)&flag));
	catpcap_destroy();
}

#endif//XTEST
