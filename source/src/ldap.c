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
		return -1;

	session_t *sess = (session_t *)data;
	char buff[128] = {0};	
	
	switch (f->type) {			
		case FT_EQ:

			snprintf(buff, sizeof(buff)-1, "%u.%u.%u.%u", NIPQUAD(sess->src_ip.addr_ip));
			buff[sizeof(buff)-1] = '\0';
			
			if (!strcmp(buff, f->s.value)) {
				ldap_debug("catch src_ip:%s\n", buff);
				return 0;
			}			
			break;

		case FT_NE:
			break;
		case FT_LT:
			break;
		case FT_GT:
			break;
		case FT_LTE:
			break;
		case FT_GTE:
			break;
		default:
			return -1;
	}

	return 1;
}

int ldap_cmp_dst_ip(filter_st *f, void *data)
{
	if (!f || !data)
		return -1;

	session_t *sess = (session_t *)data;
	char buff[128] = {0};
	
	switch (f->type) {			
		case FT_EQ:

			snprintf(buff, sizeof(buff)-1, "%u.%u.%u.%u", NIPQUAD(sess->dst_ip.addr_ip));
			buff[sizeof(buff)-1] = '\0';
			
			if (!strcmp(buff, f->s.value)) {
				ldap_debug("catch dst_ip:%s\n", buff);
				return 0;
			}	
			break;
			
		case FT_NE:
			break;
		case FT_LT:
			break;
		case FT_GT:
			break;
		case FT_LTE:
			break;
		case FT_GTE:
			break;
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
	uint16_t l = 0;
	
	switch (f->type) {			
		case FT_EQ:
			l = strtol(f->s.value, NULL, 0);
			if (ntohs(l) == sess->src_port) {
				ldap_debug("catch src_port:%u\n", l);
				return 0;
			}		
			break;
		case FT_NE:
			break;
		case FT_LT:
			break;
		case FT_GT:
			break;
		case FT_LTE:
			break;
		case FT_GTE:
			break;
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
	uint16_t l = 0;
	
	switch (f->type) {			
		case FT_EQ:
			l = strtol(f->s.value, NULL, 0);
			if (ntohs(l) == sess->dst_port) {
				ldap_debug("catch dst_port:%u\n", l);
				return 0;
			}
			break;
		case FT_NE:
			break;
		case FT_LT:
			break;
		case FT_GT:
			break;
		case FT_LTE:
			break;
		case FT_GTE:
			break;
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
			break;
		case FT_LT:
			break;
		case FT_GT:
			break;
		case FT_LTE:
			break;
		case FT_GTE:
			break;
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
