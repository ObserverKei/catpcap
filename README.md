catpcap
=========

### 简介

A. catpcap 可以用于读取pcap文件，并按照LDAP过滤条件送入用户注册的hook接口中依次处理

### 功能

A. 批量读取数据包，送入回调钩子。
B. 过滤条件支持扩展；
C. 支持5种过滤条件：对于IP包，支持按源IP，目的IP过滤，对于UDP和TCP，还支持按源端口，目的端口，协议类型过滤。这5种条件都是相等运算。
D. 支持上述条件的与、或、非运算，
E. 支持根据指定条件轮询，对符合条件的数据包调用回调钩子；

### 编译

编译文件存放在 _out
```
make
```

### 安装

安装路径：/usr/lib/ 
```
make install
```
如果想手动指定安装路径，可使用：
```
make DESTDIR=/outpath install
```

### 使用说明

```
/**
 * func:  传入pcap文件列表，依次加载pcap送入hook接口中，只传一个文件时，只处理一个文件
 * param:
 *	file_array_count	pcap文件数量
 *	file_array			pcap文件数组
 *  policy              LDAP条件触发回调，可传NULL，传NULL默认全触发
 *	hook				p_catpcap_hook_t类型的回调接口
 *	hander				送入回调的私有数据
 * return:
 *	-1: 执行出错，详细原因看报错日志
 *	 0: 执行成功
 *
**/
int catpcap(int file_array_count, char **file_array, p_catpcap_hook_t *hook, void *hander);
```

## 使用示例

可参考 source/src/demo.C

过滤 1.pcap 中 所有 UDP 协议的包 (支持=符号过滤src_ip,dst_ip,src_port,dst_port,transport)
```
./demo (transport=UDP) 1.pcap
```

## 单元测试

```
make test
```
