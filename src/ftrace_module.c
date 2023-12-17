#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/in.h>

MODULE_DESCRIPTION("LKM for monitoring netstat of the process");
MODULE_LICENSE("GPL");

struct ftrace_hook
{
	const char*   name;
	void*         function;
	void*         original;
	unsigned long address;
	struct        ftrace_ops ops;
};

typedef struct
{
	pid_t    pid;
	uint64_t bytes_received;
	uint64_t bytes_sent;
} netinfo_t;

netinfo_t process_info = { -1, 0, 0 };

static char *filename = "";
module_param(filename, charp, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = 
	{
		.symbol_name = name
	};
	unsigned long retval;
	if (register_kprobe(&kp) < 0) 
		return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs
static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#define USE_FENTRY_OFFSET 0

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
	if (!hook->address) 
	{
		printk(KERN_INFO "Ftrace module: can't hook syscall: %s.\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err = fh_resolve_hook_address(hook);
	if (err)
		return err;
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) 
	{
		printk(KERN_INFO "Ftrace module: ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}
	err = register_ftrace_function(&hook->ops);
	if (err) 
	{
		printk(KERN_INFO "Ftrace module: register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err = unregister_ftrace_function(&hook->ops);
	if (err) 
	{
		printk(KERN_INFO "Ftrace module: unregister_ftrace_function() failed: %d\n", err);
	}
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) 
	{
		printk(KERN_INFO "Ftrace module: ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;
	for (i = 0; i < count; i++) 
	{
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}
	return 0;

error:
	while (i != 0) 
		fh_remove_hook(&hooks[--i]);
	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	for (size_t i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;
	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;
	if (strncpy_from_user(kernel_filename, filename, 4096) < 0)
	{
		kfree(kernel_filename);
		return NULL;
	}
	return kernel_filename;
}

static asmlinkage long (*real_sys_send)(struct pt_regs *regs);

static asmlinkage long fh_sys_send(struct pt_regs *regs)
{
	long bytes = real_sys_send(regs);
	pid_t pid = current->pid;
	if (pid == process_info.pid && bytes > 0)
	{
		process_info.bytes_sent += bytes;
		printk(KERN_INFO "Ftrace module: process sent %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*real_sys_sendto)(struct pt_regs *regs);

static asmlinkage long fh_sys_sendto(struct pt_regs *regs)
{
	long bytes = real_sys_sendto(regs);
	pid_t pid = current->pid;
	if (pid == process_info.pid && bytes > 0)
	{
		process_info.bytes_sent += bytes;
		printk(KERN_INFO "Ftrace module: process sent %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*real_sys_sendmsg)(struct pt_regs *regs);

static asmlinkage long fh_sys_sendmsg(struct pt_regs *regs)
{
	long bytes = real_sys_sendmsg(regs);
	pid_t pid = current->pid;
	if (pid == process_info.pid && bytes > 0)
	{
		process_info.bytes_sent += bytes;
		printk(KERN_INFO "Ftrace module: process sent %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*real_sys_recv)(struct pt_regs *regs);

static asmlinkage long fh_sys_recv(struct pt_regs *regs)
{
	long bytes = real_sys_recv(regs);
	pid_t pid = current->pid;
	if (pid == process_info.pid && bytes > 0)
	{
		process_info.bytes_received += bytes;
		printk(KERN_INFO "Ftrace module: process received %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*real_sys_recvfrom)(struct pt_regs *regs);

static asmlinkage long fh_sys_recvfrom(struct pt_regs *regs)
{
	long bytes = real_sys_recvfrom(regs);
	pid_t pid = current->pid;
	if (pid == process_info.pid && bytes > 0)
	{
		process_info.bytes_received += bytes;
		printk(KERN_INFO "Ftrace module: process received %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*real_sys_recvmsg)(struct pt_regs *regs);

static asmlinkage long fh_sys_recvmsg(struct pt_regs *regs)
{
	long bytes = real_sys_recvmsg(regs);
	pid_t pid = current->pid;
	if (pid == process_info.pid && bytes > 0)
	{
		process_info.bytes_received += bytes;
		printk(KERN_INFO "Ftrace module: process received %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	if (process_info.pid == -1)
	{
		char *kernel_filename = duplicate_filename((void *)regs->di);
		char *filename_ = kernel_filename + strlen(kernel_filename) - 1;
		while (filename_ >= kernel_filename && *filename_ != '/')
		{
			--filename_;
		}
		if (strcmp(filename, ++filename_) == 0)
		{
			process_info.pid = current->pid;
			printk(KERN_INFO "Ftrace module: program %s with PID = %d executed.\n", filename, process_info.pid);
		}
		kfree(kernel_filename);
	}
	return real_sys_execve(regs);
}

static asmlinkage long (*real_sys_exit)(struct pt_regs *regs);

static asmlinkage long fh_sys_exit(struct pt_regs *regs)
{
	if (process_info.pid == current->pid)
	{
		printk(KERN_INFO "Ftrace module: process with PID = %d exited.\n", process_info.pid);
		printk(KERN_INFO "Ftrace module: received %d bytes.\n", process_info.bytes_received);
		printk(KERN_INFO "Ftrace module: sent     %d bytes.\n", process_info.bytes_sent);
	}
	return real_sys_exit(regs);
}

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original) \
{					             \
	.name = SYSCALL_NAME(_name), \
	.function = (_function),	 \
	.original = (_original),	 \
}

static struct ftrace_hook hook_array[] = 
{
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
	HOOK("sys_send", fh_sys_send, &real_sys_send),
	HOOK("sys_sendto", fh_sys_sendto, &real_sys_sendto),
	HOOK("sys_sendmsg", fh_sys_sendmsg, &real_sys_sendmsg),
	HOOK("sys_recv", fh_sys_recv, &real_sys_recv),
	HOOK("sys_recvfrom", fh_sys_recvfrom, &real_sys_recvfrom),
	HOOK("sys_recvmsg", fh_sys_recvmsg, &real_sys_recvmsg),
	HOOK("sys_exit_group", fh_sys_exit, &real_sys_exit),
};

static int __init fh_init(void)
{
	if (strlen(filename) < 1)
	{
		printk(KERN_INFO "Ftrace module: error - filename should be given.\n");
		return -1;
	}
	int err = fh_install_hooks(hook_array, ARRAY_SIZE(hook_array));
	if (!err)
	{
		printk(KERN_INFO "Ftrace module: loaded.\n");
		printk(KERN_INFO "Ftrace module: program %s is being monitored.\n", filename);
	}
	return err;
}

static void __exit fh_exit(void)
{
	fh_remove_hooks(hook_array, ARRAY_SIZE(hook_array));
	printk(KERN_INFO "Ftrace module: unloaded.\n");
}

module_init(fh_init);
module_exit(fh_exit);
