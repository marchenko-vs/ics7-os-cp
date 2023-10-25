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

#define pr_fmt(fmt) "[ptrace module] " fmt

MODULE_DESCRIPTION("LKM for monitoring netstat of the process");
MODULE_LICENSE("GPL");

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

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook
{
	const char*   name;
	void*         function;
	void*         original;
	unsigned long address;
	struct        ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) 
	{
		pr_debug("Can't hook syscall: %s.\n", hook->name);
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

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) 
	{
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) 
	{
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err = unregister_ftrace_function(&hook->ops);
	if (err) 
	{
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) 
	{
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
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
	{
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
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

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_sendto)(struct pt_regs *regs);

static asmlinkage long fh_sys_sendto(struct pt_regs *regs)
{
	long ret = real_sys_sendto(regs);
	pid_t pid = current->pid;

	if (pid == process_info.pid)
	{
		process_info.bytes_sent += ret;
	}

	return ret;
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_recvfrom)(struct pt_regs *regs);

static asmlinkage long fh_sys_recvfrom(struct pt_regs *regs)
{
	long ret = real_sys_recvfrom(regs);
	pid_t pid = current->pid;

	if (pid == process_info.pid)
	{
		process_info.bytes_received += ret;
	}

	return ret;
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	if (process_info.pid == -1)
	{
		char *kernel_filename = duplicate_filename((void *)regs->di);
		char *filename_ = kernel_filename + strlen(kernel_filename) - 1;
		while (filename_ >= kernel_filename && *filename_ != '/')
			--filename_;
		if (strcmp(filename, ++filename_) == 0)
		{
			process_info.pid = current->pid;
			pr_info("programm <<%s>> with PID = %d executed.\n", filename,
															 process_info.pid);
		}
		kfree(kernel_filename);
	}

	return real_sys_execve(regs);
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_exit)(struct pt_regs *regs);

static asmlinkage long fh_sys_exit(struct pt_regs *regs)
{
	if (process_info.pid == current->pid)
	{
		pr_info("process <<%s>> with PID = %d exited.\n", filename, 
														  process_info.pid);
		pr_info("received: %d bytes.\n", process_info.bytes_received);
		pr_info("sent: %d bytes.\n", process_info.bytes_sent);
	}

	return real_sys_exit(regs);
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = 
{
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
	HOOK("sys_sendto", fh_sys_sendto, &real_sys_sendto),
	HOOK("sys_recvfrom", fh_sys_recvfrom, &real_sys_recvfrom),
	HOOK("sys_exit_group", fh_sys_exit, &real_sys_exit),
};

static int __init fh_init(void)
{
	if (strlen(filename) < 1)
	{
		pr_info("filename should be given.\n");
		return -1;
	}

	pr_info("file <<%s>> is being monitored.\n", filename);
	int err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	
	if (!err)
		pr_info("loaded.\n");

	return err;
}

static void __exit fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("unloaded.\n");
}

module_init(fh_init);
module_exit(fh_exit);
