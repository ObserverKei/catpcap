/* 一个简单的递归向下ldap filter表达式分析器 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "ldapexpr.h"

#define ldapexpr_debug(fmt, ...) do {\
		if (g_ldapexpr_debug_enable) printf("%s %s (%d) "fmt,__FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);\
	} while (0)
	
char g_ldapexpr_debug_enable = 1;

static const char *s_ft_tab[] = {
	"=",
	"!=",
	"<",
	">",
	"<=",
	">=",
	"and",
	"or",
	"not",
};

static int opr2type(const char *opr)
{
	if (strcmp(opr, "=") == 0)
		return FT_EQ;
	
	if (strcmp(opr, "!=") == 0)
		return FT_NE;
	
	if (strcmp(opr, "<") == 0)
		return FT_LT;
	
	if (strcmp(opr, ">") == 0)
		return FT_GT;
	
	if (strcmp(opr, "<=") == 0)
		return FT_LTE;
	
	if (strcmp(opr, ">=") == 0)
		return FT_GTE;
	
	return -1;
}

static filter_st *filter_create(int ft)
{
	filter_st *ret = calloc(1, sizeof(filter_st));
	assert(ret);
	
	ret->type = ft;
	return ret;
}

void filter_destroy(filter_st *filt)
{
	if (!filt)
		return;
	
	if (filt->type == FT_AND || filt->type == FT_OR || filt->type == FT_NOT) {
		filter_destroy(filt->m.left);
		filter_destroy(filt->m.right);
	} else {
		free(filt->s.subject);
		free(filt->s.value);
	}
	
	free(filt);
}

/* 处理txt，起始位置为*pos，完成后*pos应指向未parse的新位置 */
static filter_st *filter_parse_(const char *txt, uint32_t *pos)
{
	filter_st *ret = NULL;
	char subject[128];
	char value[128];
	char opr[16];
	
	/* 所有filter都是(开始 */
	if (txt[*pos] != '(') {
		ldapexpr_debug("Filter expect a '('\n");
		return NULL;
	}
	
	(*pos)++;
	switch (txt[*pos]) {
	case '&':
	case '|':
		/* (&(X)(Y)) and or表过式第一个字符为&|，后面带两个子表达式，递归处理并赋值到left/right */
		ret = filter_create(txt[*pos] == '&' ? FT_AND : FT_OR);
		
		(*pos)++;
		
		ret->m.left = filter_parse_(txt, pos);
		if (!ret->m.left)
			goto failed;
		
		ret->m.right = filter_parse_(txt, pos);
		if (!ret->m.right)
			goto failed;
		
		break;
	case '!':
		/* (!(X)) not表达式第一个字符为!，后面带一个子表达式，存于left */
		ret = filter_create(FT_NOT);
		
		(*pos)++;
		
		ret->m.left = filter_parse_(txt, pos);
		if (!ret->m.left)
			goto failed;
		
		break;
	default:
		/* (subject?=value) 普通表达式，简单地使用sscanf获取数据 */
		if (sscanf(txt + *pos, "%127[^=!<>()\n ]%15[=!<>]%127[^)]", subject, opr, value) != 3) {
			ldapexpr_debug("Filter format error\n");
			goto failed;
		}
		
		int type = opr2type(opr);
		if (type < 0) {
			ldapexpr_debug("Filter operator not supported: %s\n", opr);
			goto failed;
		}
		
		/* 定位到当前表达式的)处 */
		const char *end = strchr(txt + *pos, ')');
		if (!end) {
			ldapexpr_debug("Filter is not closed with ')'\n");
			goto failed;
		}
		
		ret = filter_create(type);
		ret->s.subject = strdup(subject);
		ret->s.value = strdup(value);
		
		/* 更新*pos为)的位置 */
		*pos = (end - txt);
		break;
	}
	
	/* 所有filter都是)结束 */
	if (txt[*pos] != ')') {
		ldapexpr_debug("Filter expect a '('\n");
		goto failed;
	}
	(*pos)++;
	return ret;
	
failed:
	filter_destroy(ret);
	return NULL;
}

filter_st *filter_parse(const char *txt)
{
	uint32_t pos = 0;
	filter_st *filt = filter_parse_(txt, &pos);
	
	if (txt[pos] != 0) {
		ldapexpr_debug("Unexpected %s\n", txt + pos);
		filter_destroy(filt);
		return NULL;
	}
	
	return filt;
}

static void filter_debug_(filter_st *f, int s)
{
	int i;
	for (i = 0; i < s; ++i)
		ldapexpr_debug("  ");
	
	ldapexpr_debug("%s", s_ft_tab[f->type]);
	if (f->type == FT_AND || f->type == FT_OR) {
		ldapexpr_debug("\n");
		filter_debug_(f->m.left, s + 1);
		filter_debug_(f->m.right, s + 1);
	} else if (f->type == FT_NOT) {
		ldapexpr_debug("\n");
		filter_debug_(f->m.left, s + 1);
	} else {
		ldapexpr_debug(" %s %s\n", f->s.subject, f->s.value);
	}
}

// return 0 相等， 1 不相等，-1无法比较
int catpcap_cmp_eq(filter_st *f, int s, session_t *sess)
{
	if (!strcmp("src_ip", f->s.subject)) {
		
		char buff[128] = {0};
		snprintf(buff, sizeof(buff)-1, "%u.%u.%u.%u", NIPQUAD(sess->src_ip.addr_ip));
		buff[sizeof(buff)-1] = '\0';
		
		if (!strcmp(buff, f->s.value)) {
			ldapexpr_debug("catch src_ip:%s\n", buff);
			return 0;
		}
	} else if (!strcmp("dst_ip", f->s.subject)) {
		
		char buff[128] = {0};
		snprintf(buff, sizeof(buff)-1, "%u.%u.%u.%u", NIPQUAD(sess->dst_ip.addr_ip));
		buff[sizeof(buff)-1] = '\0';
		
		if (!strcmp(buff, f->s.value)) {
			ldapexpr_debug("catch dst_ip:%s\n", buff);
			return 0;
		}
		
	} else if (!strcmp("src_port", f->s.subject)) {
		
		uint16_t l = strtol(f->s.value, NULL, 0);
		if (ntohs(l) == sess->src_port) {
			ldapexpr_debug("catch src_port:%u\n", l);
			return 0;
		}
			
	} else if (!strcmp("dst_port", f->s.subject)) {
		
		uint16_t l = strtol(f->s.value, NULL, 0);
		if (ntohs(l) == sess->dst_port) {
			ldapexpr_debug("catch dst_port:%u\n", l);
			return 0;
		}
			
	} else if (!strcmp("transport", f->s.subject)) {
		//ldapexpr_debug("detect transport: start: %s\n", f->s.subject);
		switch (sess->transport) {
			case SESSION_TRANSPORT_TCP:
				if (!strcmp("TCP", f->s.value)) {
					ldapexpr_debug("catch transport:%s\n", f->s.value);
					return 0;
				}
			case SESSION_TRANSPORT_UDP:
				if (!strcmp("UDP", f->s.value)) {
					ldapexpr_debug("catch transport:%s\n", f->s.value);
					return 0;
				}
			case SESSION_TRANSPORT_ICMP: 
				if (!strcmp("ICMP", f->s.value)) {
					ldapexpr_debug("catch transport:%s\n", f->s.value);
					return 0;
				}
			default:
				ldapexpr_debug("SESSION_TRANSPORT_UNKNOW\n");
				return -1;
		}
	} 
	ldapexpr_debug("detect fail:%s %s\n", f->s.subject, f->s.value);
	
	return 1;
}

// return 0 匹配成功，其他：匹配失败
static int filter_catpcap(filter_st *f, int s, session_t *sess)
{
	if (!f || !sess)
		return -2;
	
	int ret_left = 0;
	int ret_right = 0;
	
	switch (f->type) {
		case FT_AND:
			ret_left = filter_catpcap(f->m.left, s + 1, sess);
			ret_right = filter_catpcap(f->m.right, s + 1, sess);
			if ((!ret_left) && (!ret_right))
				return 0;
		case FT_OR:
			ret_left = filter_catpcap(f->m.left, s + 1, sess);
			ret_right = filter_catpcap(f->m.right, s + 1, sess);
			if ((!ret_left) || (!ret_right))
				return 0;
		case FT_NOT:
			ret_left = filter_catpcap(f->m.left, s + 1, sess);
			if (1 == ret_left)
				return 0;
		case FT_EQ:
			return catpcap_cmp_eq(f, s, sess);
		case FT_NE:
		case FT_LT:
		case FT_GT:
		case FT_LTE:
		case FT_GTE:
		default:
			ldapexpr_debug("CAN'T USE f->type");
			return -1;
	}
	
	return -3;
}

// return 0匹配成功，其他匹配失败
int filter_check(filter_st *f, session_t *sess)
{
	return filter_catpcap(f, 0, sess);
}

/* 查看filter */
void filter_debug(filter_st *filt)
{
	filter_debug_(filt, 0);
}

#ifdef _XTEST_DEMO

int main(int argc, char **argv)
{
	filter_st *filt = filter_parse(argv[1]);
	if (!filt)
		return 1;
	
	filter_debug(filt);
	filter_destroy(filt);
	return 0;
}

#endif//_ZTEST_DEMO