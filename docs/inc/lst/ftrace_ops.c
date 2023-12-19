struct ftrace_ops fops = {
    .func    = my_callback_func,
    .flags   = MY_FTRACE_FLAGS,
    .private = any_private_data_structure,
};
