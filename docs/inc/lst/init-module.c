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
