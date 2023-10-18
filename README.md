# ebpf_cout_call

ebpf_count_call is a small go program that will count how many time execve syscall has been call since the module has been load in the Kernel.

The code is a bit messy but the idea here was jusst to play with bpf maps and learn how to read them in user-land.

Some part needs improvement like the infinite loop, or the fact that `bpf_map_def` needed to be define (did not find which package to include)
