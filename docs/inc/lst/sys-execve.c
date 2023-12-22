static asmlinkage long (*original_sys_execve)(struct pt_regs *regs);

static asmlinkage long hook_sys_execve(struct pt_regs *regs)
{
	if (statistics.pid == -1)
	{
		char *kernel_fname = dup_filename((void *)regs->di);
		char *fname_ = kernel_fname + strlen(kernel_fname) - 1;
		while (fname_ >= kernel_fname && *fname_ != '/')
			--fname_;
		if (strcmp(fname, ++fname_) == 0)
		{
			statistics.pid = current->pid;
			printk(KERN_INFO "Traffic module: program %s with PID = %d executed.\n", fname, statistics.pid);
		}
		kfree(kernel_fname);
	}
	return original_sys_execve(regs);
}
