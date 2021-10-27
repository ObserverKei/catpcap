#ifndef __CATPCAP_H__
#define __CATPCAP_H__

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

#include <stdint.h>
#include "session.h"

typedef int p_catpcap_hook_t(void *hander, session_t *sess, uint8_t dir, const char *data, uint16_t data_len);

/**
 * func:  传入pcap文件列表，依次加载pcap送入hook接口中，只传一个文件时，只处理一个文件
 * param:
 *	file_array_count	pcap文件数量
 *	file_array			pcap文件数组
 *	policy				ldap表达式，选择如何命中回调，传NULL默认全命中
 *	hook				p_catpcap_hook_t类型的回调接口
 *	hander				送入回调的私有数据
 * return:
 *	-1: 执行出错，详细原因看报错日志
 *	 0: 执行成功
 *
**/
int catpcap(int file_array_count, char **file_array, const char *policy, p_catpcap_hook_t *hook, void *hander);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//__CATPCAP_H__
