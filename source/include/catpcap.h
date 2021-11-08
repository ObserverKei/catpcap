#ifndef __CATPCAP_H__
#define __CATPCAP_H__

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

#include <stdint.h>
#include "session.h"

typedef int p_catpcap_hook_t(void *hander, session_t *sess, uint8_t dir, const char *data, uint16_t data_len);


/*
 * func:  初始化catpcap接口，需要传文件以及LDAP表达式
 * param:
 *	file_array_count	pcap文件数量
 *	file_array			pcap文件数组
 *	policy				ldap表达式，选择如何命中回调，传NULL默认全命中
 * return:
 *	<0: 初始化出错，详细原因看报错日志
 *	 0: 执行初始化成功
*/
int catpcap_init(int file_array_count, char **file_array, const char *policy);

/*
 * func:  销毁catpcap_init初始化操作
 *
 */
void catpcap_destroy(void);

/**
 * func:  批量处理数据包，并执行回调，将hander送入回调中,支持遍历pcap文件中的某一条数据包。需要先catpcap_init初始化，不可以和catpcap同时使用
 * param:
 *	file_idx			需要处理pcap文件列表中的第几个文件
 *	pcaket_idx			需要处理pcap文件中的第几个包
 *	hook				p_catpcap_hook_t 类型的回调接口
 *	hander				送入回调的私有数据, 返回0表示继续处理pcap文件中的下一个pcap包
 * return:
 *	<0: 执行出错，详细原因看报错日志
 *	 0: 执行成功
 *
**/
int catpcap_idx(size_t file_idx, size_t pcaket_idx, p_catpcap_hook_t *hook, void *hander);

/**
 * func:  批量处理数据包，并执行回调，将hander送入回调中。需要先catpcap_init初始化，不可以和catpcap_idx同时使用
 * param:
 *	hook				p_catpcap_hook_t 类型的回调接口
 *	hander				送入回调的私有数据
 * return:
 *	<0: 执行出错，详细原因看报错日志
 *	 0: 执行成功
 *
**/
int catpcap(p_catpcap_hook_t *hook, void *hander);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//__CATPCAP_H__
