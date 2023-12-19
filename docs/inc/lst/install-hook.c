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
