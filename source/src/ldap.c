#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>


#include "ldapexpr/ldapexpr.h"
#include "session.h"

#define ldap_debug(fmt, ...) do {\
		if (g_ldap_debug_enable) printf("%s %s (%d) "fmt,__FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);\
	} while (0)

char g_ldap_debug_enable = 1;


int ldap_cmp_src_ip(filter_st *f, void *data)
{
	if (!f || !data)
		return -2;

	session_t *sess = (session_t *)data;	
	union {
		uint32_t addr_ip;
		uint8_t ipv4_all[4];
	} ip;

	if (4 != sscanf(f->s.value, "%hhu.%hhu.%hhu.%hhu", &ip.ipv4_all[0], &ip.ipv4_all[1], 
		&ip.ipv4_all[2], &ip.ipv4_all[3])) 
		return -2;
	
	switch (f->type) {			
		case FT_EQ:
			return !(sess->src_ip.addr_ip == ip.addr_ip);
		case FT_NE:
			return !(sess->src_ip.addr_ip != ip.addr_ip);
		case FT_LT:
			return !(sess->src_ip.addr_ip > ip.addr_ip);
		case FT_GT:
			return !(sess->src_ip.addr_ip < ip.addr_ip);
		case FT_LTE:
			return !(sess->src_ip.addr_ip <= ip.addr_ip);
		case FT_GTE:
			return !(sess->src_ip.addr_ip >= ip.addr_ip);
		default:
			return -1;
	}

	return 1;
}

int ldap_cmp_dst_ip(filter_st *f, void *data)
{
	if (!f || !data)
		return -2;

	session_t *sess = (session_t *)data;	
	union {
		uint32_t addr_ip;
		uint8_t ipv4_all[4];
	} ip;

	if (4 != sscanf(f->s.value, "%hhu.%hhu.%hhu.%hhu", &ip.ipv4_all[0], &ip.ipv4_all[1], 
		&ip.ipv4_all[2], &ip.ipv4_all[3]))
		return -2;
	
	switch (f->type) {			
		case FT_EQ:
			return !(sess->dst_ip.addr_ip == ip.addr_ip);
		case FT_NE:
			return !(sess->dst_ip.addr_ip != ip.addr_ip);
		case FT_LT:
			return !(sess->dst_ip.addr_ip > ip.addr_ip);
		case FT_GT:
			return !(sess->dst_ip.addr_ip < ip.addr_ip);
		case FT_LTE:
			return !(sess->dst_ip.addr_ip <= ip.addr_ip);
		case FT_GTE:
			return !(sess->dst_ip.addr_ip >= ip.addr_ip);
		default:
			return -1;
	}

	return 1;
}

int ldap_cmp_src_port(filter_st *f, void *data)
{
	if (!f || !data)
		return -1;

	session_t *sess = (session_t *)data;
	uint16_t l = strtol(f->s.value, NULL, 0);
	uint16_t src_port = ntohs(sess->src_port);
	
	switch (f->type) {			
		case FT_EQ:
			return !(src_port == l);
		case FT_NE:
			return !(src_port != l);
		case FT_LT:
			return !(src_port < l);
		case FT_GT:
			return !(src_port > l);
		case FT_LTE:
			return !(src_port <= l);
		case FT_GTE:
			return !(src_port >= l);
		default:
			return -1;
	}

	return 1;
}

int ldap_cmp_dst_port(filter_st *f, void *data)
{
	if (!f || !data)
		return -1;

	session_t *sess = (session_t *)data;
	uint16_t l = strtol(f->s.value, NULL, 0);
	uint16_t dst_port = ntohs(sess->dst_port);

	switch (f->type) {			
		case FT_EQ:
			return !(dst_port == l);
		case FT_NE:
			return !(dst_port != l);
		case FT_LT:
			return !(dst_port < l);
		case FT_GT:
			return !(dst_port > l);
		case FT_LTE:
			return !(dst_port <= l);
		case FT_GTE:
			return !(dst_port >= l);
		default:
			return -1;
	}

	return 1;
}

int ldap_cmp_transport(filter_st *f, void *data)
{
	if (!f || !data)
		return -1;

	session_t *sess = (session_t *)data;
	
	switch (f->type) {			
		case FT_EQ:
			ldap_debug("detect transport: start: %s, sess: %d\n", f->s.subject, sess->transport);
			switch (sess->transport) {
				case SESSION_TRANSPORT_TCP:
					if (!strcmp("TCP", f->s.value)) {
						ldap_debug("catch transport:%s\n", f->s.value);
						return 0;
					}
					break;
				case SESSION_TRANSPORT_UDP:
					ldap_debug("udp cmp:%s\n", f->s.value);
					if (!strcmp("UDP", f->s.value)) {
						ldap_debug("catch transport:%s\n", f->s.value);
						return 0;
					}
					ldap_debug("udp cmp:%s done\n", f->s.value);
					
					break;
				case SESSION_TRANSPORT_ICMP: 
					if (!strcmp("ICMP", f->s.value)) {
						ldap_debug("catch transport:%s\n", f->s.value);
						return 0;
					}
					break;
				default:
					ldap_debug(" transport: UNKNOW\n");
					return -1;
			}			
			break;
		case FT_NE:
		case FT_LT:
		case FT_GT:
		case FT_LTE:
		case FT_GTE:
		default:
			return -1;
	}

	return 1;
}

ldapexpr_hook_kv_t s_catpcap_cmp_hook[] = {
	{"src_ip", ldap_cmp_src_ip},
	{"dst_ip", ldap_cmp_dst_ip},
	{"src_port", ldap_cmp_src_port},
	{"dst_port", ldap_cmp_dst_port},
	{"transport", ldap_cmp_transport},
};

int ldap_init(void) {
	int ret = 0;
	int i = 0;
	for (i = 0; i < sizeof(s_catpcap_cmp_hook)/sizeof(s_catpcap_cmp_hook[0]); ++i) {
		ret = add_ldapexpr_cmp(&s_catpcap_cmp_hook[i]);
		if (ret)
			return -1;
	}

	return 0;
}
