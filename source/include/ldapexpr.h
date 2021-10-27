#ifndef	__LDAPEXPR_H__
#define	__LDAPEXPR_H__

#ifdef	__cplusplus
extern "C" {
#endif//__cplusplus

#include "session.h"

typedef struct filter_st {
	enum {
		FT_EQ,		/* = */
		FT_NE,		/* != */
		FT_LT,		/* < */
		FT_GT,		/* > */
		FT_LTE,		/* <= */
		FT_GTE,		/* >= */
		
		FT_AND,		/* 复合过滤器 & */
		FT_OR,		/* 复合过滤器 | */
		FT_NOT,		/* 复合过滤器 ! */
	} type;
	
	union {
		struct {
			struct filter_st *left;
			struct filter_st *right;
		} m;		/* 复合过滤器时使用 */
		struct {
			char *subject;
			char *value;
		} s;		/* 非复合过滤时使用 */
	};
} filter_st;

//匹配资源申请，传参LDAP字符串表达式
filter_st *filter_parse(const char *txt);
//命中返回0，否则返回其他，传参匹配资源和连接跟踪
int filter_check(filter_st *f, session_t *sess);
//资源释放
void filter_destroy(filter_st *filt);


#ifdef	__cplusplus
}
#endif//__cplusplus

#endif//__LDAPEXPR_H__