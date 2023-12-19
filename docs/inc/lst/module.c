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

#define OFFSET 0

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LKM for monitoring network traffic of a process");

struct hook
{
	const char*       name;
	void*             function;
	void*             original;
	unsigned long     address;
	struct ftrace_ops ops;
};

struct net_traffic
{
	pid_t    pid;
	uint64_t bytes_received;
	uint64_t bytes_sent;
};

struct net_traffic statistics = { -1, 0, 0 };

static char *fname = "";
module_param(fname, charp, 0);

static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = 
	{
		.symbol_name = name
	};
	unsigned long address;
	if (register_kprobe(&kp) < 0) 
		return 0;
	address = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return address;
}

static int resolve_hook_address(struct hook *hook)
{
	hook->address = lookup_name(hook->name);
	if (!hook->address) 
	{
		printk(KERN_INFO "Traffic module: can't hook syscall: %s.\n", hook->name);
		return -ENOENT;
	}
#if OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif
	return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
	struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct hook *hook = container_of(ops, struct hook, ops);
#if OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

int install_hook(struct hook *hook)
{
	int err = resolve_hook_address(hook);
	if (err)
		return err;
	hook->ops.func = ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) 
	{
		printk(KERN_INFO "Traffic module: can't ftrace_set_filter_ip: %d\n", err);
		return err;
	}
	err = register_ftrace_function(&hook->ops);
	if (err) 
	{
		printk(KERN_INFO "Traffic module: can't register_ftrace_function: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	return 0;
}

void uninstall_hook(struct hook *hook)
{
	int err = unregister_ftrace_function(&hook->ops);
	if (err) 
		printk(KERN_INFO "Traffic module: can't unregister_ftrace_function: %d\n", err);
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) 
		printk(KERN_INFO "Traffic module: can't ftrace_set_filter_ip: %d\n", err);
}

int install_hooks(struct hook *hooks, size_t count)
{
	int err = 0;
	size_t i;
	for (i = 0; err == 0 && i < count; i++)
		err = install_hook(&hooks[i]);
	if (err)
		while (i != 0) 
			uninstall_hook(&hooks[--i]);
	return err;
}

void uninstall_hooks(struct hook *hooks, size_t count)
{
	for (size_t i = 0; i < count; i++)
		uninstall_hook(&hooks[i]);
}

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static char *dup_filename(const char __user *filename)
{
	char *kernel_fname = kmalloc(4096, GFP_KERNEL);
	if (!kernel_fname)
		return NULL;
	if (strncpy_from_user(kernel_fname, filename, 4096) < 0)
	{
		kfree(kernel_fname);
		return NULL;
	}
	return kernel_fname;
}

static asmlinkage long (*original_sys_send)(struct pt_regs *regs);

static asmlinkage long hook_sys_send(struct pt_regs *regs)
{
	long bytes = original_sys_send(regs);
	pid_t pid = current->pid;
	if (pid == statistics.pid && bytes > 0)
	{
		statistics.bytes_sent += bytes;
		printk(KERN_INFO "Traffic module: process sent %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*original_sys_sendto)(struct pt_regs *regs);

static asmlinkage long hook_sys_sendto(struct pt_regs *regs)
{
	long bytes = original_sys_sendto(regs);
	pid_t pid = current->pid;
	if (pid == statistics.pid && bytes > 0)
	{
		statistics.bytes_sent += bytes;
		printk(KERN_INFO "Traffic module: process sent %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*original_sys_sendmsg)(struct pt_regs *regs);

static asmlinkage long hook_sys_sendmsg(struct pt_regs *regs)
{
	long bytes = original_sys_sendmsg(regs);
	pid_t pid = current->pid;
	if (pid == statistics.pid && bytes > 0)
	{
		statistics.bytes_sent += bytes;
		printk(KERN_INFO "Traffic module: process sent %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*original_sys_recv)(struct pt_regs *regs);

static asmlinkage long hook_sys_recv(struct pt_regs *regs)
{
	long bytes = original_sys_recv(regs);
	pid_t pid = current->pid;
	if (pid == statistics.pid && bytes > 0)
	{
		statistics.bytes_received += bytes;
		printk(KERN_INFO "Traffic module: process received %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*original_sys_recvfrom)(struct pt_regs *regs);

static asmlinkage long hook_sys_recvfrom(struct pt_regs *regs)
{
	long bytes = original_sys_recvfrom(regs);
	pid_t pid = current->pid;
	if (pid == statistics.pid && bytes > 0)
	{
		statistics.bytes_received += bytes;
		printk(KERN_INFO "Traffic module: process received %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*original_sys_recvmsg)(struct pt_regs *regs);

static asmlinkage long hook_sys_recvmsg(struct pt_regs *regs)
{
	long bytes = original_sys_recvmsg(regs);
	pid_t pid = current->pid;
	if (pid == statistics.pid && bytes > 0)
	{
		statistics.bytes_received += bytes;
		printk(KERN_INFO "Traffic module: process received %ld bytes.\n", bytes);
	}
	return bytes;
}

static asmlinkage long (*original_sys_execve)(struct pt_regs *regs);

static asmlinkage long hook_sys_execve(struct pt_regs *regs)
{
	if (statistics.pid == -1)
	{
		char *kernel_fname = dup_filename((void *)regs->di);
		char *fname_ = kernel_fname + strlen(kernel_fname) - 1;
		while (fname_ >= kernel_fname && *fname_ != '/')
		{
			--fname_;
		}
		if (strcmp(fname, ++fname_) == 0)
		{
			statistics.pid = current->pid;
			printk(KERN_INFO "Traffic module: program %s with PID = %d executed.\n", fname, statistics.pid);
		}
		kfree(kernel_fname);
	}
	return original_sys_execve(regs);
}

static asmlinkage long (*original_sys_exit)(struct pt_regs *regs);

static asmlinkage long hook_sys_exit(struct pt_regs *regs)
{
	if (statistics.pid == current->pid)
	{
		printk(KERN_INFO "Traffic module: process with PID = %d exited.\n", statistics.pid);
		printk(KERN_INFO "Traffic module: received %d bytes.\n", statistics.bytes_received);
		printk(KERN_INFO "Traffic module: sent     %d bytes.\n", statistics.bytes_sent);
	}
	return original_sys_exit(regs);
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

static struct hook hook_array[] = 
{
	HOOK("sys_execve", hook_sys_execve, &original_sys_execve),
	HOOK("sys_send", hook_sys_send, &original_sys_send),
	HOOK("sys_sendto", hook_sys_sendto, &original_sys_sendto),
	HOOK("sys_sendmsg", hook_sys_sendmsg, &original_sys_sendmsg),
	HOOK("sys_recv", hook_sys_recv, &original_sys_recv),
	HOOK("sys_recvfrom", hook_sys_recvfrom, &original_sys_recvfrom),
	HOOK("sys_recvmsg", hook_sys_recvmsg, &original_sys_recvmsg),
	HOOK("sys_exit_group", hook_sys_exit, &original_sys_exit),
};

static int __init traffic_init(void)
{
	if (strlen(fname) < 1)
	{
		printk(KERN_INFO "Traffic module: error - incorrect filename.\n");
		return -1;
	}
	int err = install_hooks(hook_array, ARRAY_SIZE(hook_array));
	if (!err)
	{
		printk(KERN_INFO "Traffic module: loaded.\n");
		printk(KERN_INFO "Traffic module: program %s is monitored.\n", fname);
	}
	return err;
}

static void __exit traffic_exit(void)
{
	uninstall_hooks(hook_array, ARRAY_SIZE(hook_array));
	printk(KERN_INFO "Traffic module: unloaded.\n");
}

module_init(traffic_init);
module_exit(traffic_exit);
