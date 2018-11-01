* 隐藏rootkit自身 将rootkit的信息结构体从全局内核模块信息链表中删除
* 隐藏包含命令行和执行文件名称中包含特定字符串的进程 在getdents和getdents64调用时候过滤，判断/prco/pid/cmd和/proc/pid/comm的内容
* 根据pid指定需要隐藏的进程，通过kill调用 hook kill调用，如果是定义的特定信号，添加目标pid到需要屏蔽的pid链表
* 隐藏被隐藏进程的tcp连接 hook /proc/net/tcp的show函数，通过被隐藏进程的/proc/pid/fd文件夹加载需要被屏蔽的tcp的inode信息，过滤这些tcp信息
* 隐藏包含特定后缀的文件 在getdents和getdents64中过滤特定后缀的目录项
* 隐藏特定tag内的文件内容 在read调用处过滤特定tag间的内容，会对文件引用尝试获取，如果大于1则说明可能是高IO文件，为不对性能产生显著影响，不做处理
* 监视网络发送 hook send系统调用
* 监视新的内核模块加载 注册内核模块变动通知函数
* 监视特定网络包，当端口，协议和包内容符合时，开启后门 注册最开始阶段的网络包处理函数，如果是特定网络包，则解析并drop
* 特定程序通过kill调用获得root权限 hook kill调用，特定信号将目前进程权限改为root
* 通过kill调用控制rootkit行为 hook kill调用并定义自定义信号