#include <sys/ptrace.h>

long ptrace(enum __ptrace_request request, pid_t pid, 
            void *addr, void *data);
