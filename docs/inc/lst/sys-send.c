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
