#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "catpcap.h"

typedef struct hander_st {
	int flag;
} hander_t;

int catpcap_hook(void *hander, session_t *sess, uint8_t dir, const char *data, uint16_t data_len) {
	if (!hander || !data || !sess)
		return -1;
	hander_t *ph = (hander_t *)hander;

	printf("--\n%s, %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\nuser data len: %d, flag: %d\n", sess->transport == SESSION_TRANSPORT_TCP ? "TCP":"UDP", 
			NIPQUAD(sess->src_ip.addr_ip), ntohs(sess->src_port), 
			NIPQUAD(sess->dst_ip.addr_ip), ntohs(sess->dst_port), data_len, ph->flag);
	
	
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("use: demo policy pcapfile\n");
		return -1;
	}
	char idx = 1;//pcap文件传参偏移
	const char *policy = NULL;
	if (argc > 2 && (NULL == strstr(argv[1], ".pcap"))) {
		policy = argv[1];
		++idx;
	}
	hander_t flag = { .flag = 1};
	char **file_array = argv + idx;
	int file_array_count = argc - idx;

	int ret = catpcap(file_array_count, file_array, policy, catpcap_hook, (void *)&flag);
	return ret;
}
