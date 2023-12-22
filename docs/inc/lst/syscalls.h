#include <linux/syscalls.h>

asmlinkage long sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);
asmlinkage long sys_send(int, void __user *, size_t, unsigned);
asmlinkage long sys_sendto(int, void __user *, size_t, 
	unsigned, struct sockaddr __user *, int);
asmlinkage long sys_sendmsg(int fd, 
	struct user_msghdr __user *msg, unsigned flags);
asmlinkage long sys_recv(int, void __user *, size_t, unsigned);
asmlinkage long sys_recvfrom(int, void __user *, 
	size_t, unsigned, struct sockaddr __user *, int __user *);
asmlinkage long sys_recvmsg(int fd, 
	struct user_msghdr __user *msg, unsigned flags);
asmlinkage long sys_exit_group(int error_code);
