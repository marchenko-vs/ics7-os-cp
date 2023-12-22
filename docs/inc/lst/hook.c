struct hook {
	const char*       name;
	void*             function;
	void*             original;
	unsigned long     address;
	struct ftrace_ops ops;
};
