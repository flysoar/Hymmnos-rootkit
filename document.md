# hymmnos rootkit 文档

## 功能
1. 隐藏rootkit自身
2. 隐藏包含命令行和执行文件名称中包含特定字符串的进程
3. 根据pid指定需要隐藏的进程，通过kill调用
4. 隐藏被隐藏进程的tcp连接
5. 隐藏包含特定后缀的文件
6. 隐藏特定tag内的文件内容，例如<touwaka>和</touwaka>之间的内容会被隐藏，可以利用该功能在init.d中添加开机启动且隐藏。
7. 监视网络发送，搜集包括特定内容的包并记录，目前会记录http请求和可能包含密码的内容，保存在etc目录下
8. 监视新的内核模块加载，目前hook住新内核加载的加载函数和卸载函数，并直接返回
9. 监视特定网络包，当端口，协议和包内容符合时，开启后门，paket结构为（magic+空格+ip+port），rootkit在接受到包时，将以-a ip -p port作为命令行参数，执行预定程序。预定程序可以解析这些参数并反弹回shell。
10. 特定程序通过kill调用获得root权限
11. 通过kill调用控制rootkit行为

## 详细文档

### 基础辅助函数
#### file_open
打开一个文件返回file结构，open函数的内核实现
#### file_close
close函数的内核实现
#### file_read
read函数的内核实现
#### file_write
write函数的内核实现
#### file_sync
sync函数的内核实现
#### make_rw
通过查找指定地址的页表，并设置权限为可写
#### make_ro
通过查找指定地址的页表，并设置权限为只读
#### read_whole_file
直接读写整个文件的内容，只适合读写文件内容不大的文件，在使用完成后，需要手动销毁缓冲区
#### read_n_bytes_of_file
读取n字节文件内容，需要手动销毁缓冲区

### 隐藏文件与进程功能
#### check_file_suffix
确定文件名称是否满足特定后缀
#### is_int
确定是否为数字
#### is_pid_hidden
该pid进程是否被隐藏，rootkit使用了一个双向链表保存被制定隐藏的进程
#### make_pid_hidden
将该进程隐藏，如果已经被隐藏，直接返回
#### make_pid_show
解除该pid的隐藏
#### clean_hidden_pids
清除pid链表，释放内存
#### check_process_name
确定该进程可执行文件是否包含特定字符串
#### check_process_prefix
确定该进程是否饱和特定字符串在可执行文件名称或命令行中，并确定该进程是否是被指定需要隐藏的进程
#### check_file_name
确定该文件是否是rootkit文件
#### should_be_hidden
确定一个目录项是否需要被隐藏
#### new_sys_getdents
对getdents的hook函数，检查是否有需要被隐藏的的目录项目并进行隐藏
#### new_sys_getdents64
对getdents64的hook函数，检查是否有需要被隐藏的的目录项目并进行隐藏

### packet记录模块
#### save_to_log
保存内容到指定的的文件
#### password_found
检查是否可能包含密码
#### http_header_found
检查是否包含http头
#### new_sys_sendto
对send函数进程hook，并对进程进行检查，如果包含感兴趣的内容则保存

### 隐藏port功能
#### is_inode_hidden
对于需要被隐藏的port，记录下他们的inode信息，使用一个单向链表进行记录
#### make_inode_hidden
添加新的inode信息到链表中
#### clean_hidden_inodes
清空inode信息链表
#### extract_type_1_socket_inode
从socket:[12345]中提取12345，该数字即是inode节点
#### load_inodes_of_process
检查需要被隐藏进程的fd，如果fd中存在软连接到socket的，软链接的目标将是类似socket:[12345]的形式，12345即是socket的inode节点，将这些inode节点记录下来
#### load_inodes_to_hide
从需要被隐藏的进程中寻找需要被隐藏的socket结点
#### next_column
读取下一行，帮助函数
#### new_seq_show
对/proc/net/tcp文件对show函数对hook函数，该文件是特殊文件，通过他可以获得tcp连接信息。调用原始函数后，对内容进行过滤，删除掉需要被隐藏对inode对条目

### 隐藏特定内容模块
#### f_check
确定是否包含特定tag
#### hide_content
删除特定tag间的内容
#### e_fget_light
轻量对获取特定fd对引用， 该函数的目的是降低对性能对影响
#### new_sys_read
对read调用的hook，该函数会预先尝试获得该文件对锁，失败时不做处理，这样做的原因是，需要隐藏特定内容对文件一般是不经常被读写的，所以可以获取锁，而对于高IO的文件可以降低性能影响

### 网络后门功能
#### s_xor
对缓冲区每个字符串进行异或，混淆流量
#### atoi
转化为int
#### exec
在用户态执行命令
#### shell_execer
执行shell
#### shell_exec_queue
准备好work queen数据结构，将shell执行任务放入工作队列中
#### decode_n_spawn
对缓冲区进行xor解码
#### magic_packet_hook
注册为packet处理函数，并在最开始阶段对packet进行处理，如果是特定结构packet进行处理并drop，否则传递给下一个阶段
#### regist_backdoor
注册后门
#### unregist_backdoor
取消对后门的注册

### 内核模块隐藏功能
#### hide
隐藏内核模块，通过将该模块从模块信息链表上删除
#### show
恢复内核模块，通过将该模块信息加入模块信息链表

### 内核模块监视功能
#### fake_init，fake_exit
替换其他模块的init和exit
#### module_notifier
需要被注册的模块notifier函数，简单的替换新加入模块的init和exit函数以组织模块的添加
#### regist_komon，unregist_komon
注册与接触注册模块notifier

### 控制与root后门功能
#### new_sys_kill
对kill调用进行hook，负责控制，使用未被使用的信息号数，
* 48 获得root权限
* 49 隐藏/显示指定进程
* 50 隐藏/显示本模块
* 51 开启/关闭特定文件内容隐藏
* 52 开启/关闭网络后门
* 53 开启/关闭新内核模块载入监视与组织

### 初始化功能
#### acquire_sys_call_table
查找系统调用表，通过对close函数的标记查找
#### create_file
创建文件
#### create_files
创建记录文件
#### rootkit_start
rootkit的init函数
#### rootkit_end
rootkit的uninit函数

