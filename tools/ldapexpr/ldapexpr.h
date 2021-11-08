#ifndef	__LDAPEXPR_H__
#define	__LDAPEXPR_H__

#ifdef	__cplusplus
extern "C" {
#endif//__cplusplus

typedef struct filter_st filter_st;

typedef enum ft_type_et {
	FT_EQ,		/* = */
	FT_NE,		/* != */
	FT_LT,		/* < */
	FT_GT,		/* > */
	FT_LTE, 	/* <= */
	FT_GTE, 	/* >= */
	
	FT_AND, 	/* 复合过滤器，不需要指定 & */
	FT_OR,		/* 复合过滤器，不需要指定 | */
	FT_NOT, 	/* 复合过滤器，不需要指定 ! */
	FT_MAXSIZE, /* 大小 */
} ft_type_t;

typedef struct ldapexpr_ftv_st {
	ft_type_t type;              /* 被比较的输入类型, */
	const char *value;           /* 被比较的输入值 */
} ldapexpr_ftv_t;

/* 比较回调函数，return 0 匹配，1不匹配，-1 比较类型不支持，<0 其他错误 */
typedef int ldapexpr_hook_t(ldapexpr_ftv_t *ftv, void *data);

typedef struct ldapexpr_hook_kv_st {
	const char *cmp_key;         /* 被比较的key值 */
	ldapexpr_hook_t *hook;       /* 进行比较的回调函数 */
} ldapexpr_hook_kv_t;

/** 
 * func: 添加新的字段比较回调
 * param:
 *        new_ldapexpr_hook_kv  需要注册的比较接口
 * return 0 添加成功
 *       -1 添加失败
 *
 */
int add_ldapexpr_cmp(ldapexpr_hook_kv_t *new_ldapexpr_hook_kv);


//匹配资源申请，传参LDAP字符串表达式
filter_st *filter_init(const char *txt);
//命中返回0，否则返回其他，传参匹配资源和连接跟踪
int filter_check(filter_st *f, void *data);
//资源释放
void filter_destroy(filter_st *filt);


#ifdef	__cplusplus
}
#endif//__cplusplus

#endif//__LDAPEXPR_H__
