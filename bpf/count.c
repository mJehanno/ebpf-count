// #include "vmlinux.h"
// #include <bpf/bpf_core_read.h>
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <linux/bpf.h>
// #include <linux/types.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
  unsigned int map_flags;
	unsigned int pinning;

} bpf_map_def;

char __license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1000,
};
// bpf_map_def

// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __type(key, __u32);
//   __type(value, struct record);
//   __uint(max_entries, 1);
// } count_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_syscall(void *ctx) {
  __u32 key =0;
  __u32 *counter = NULL;

  counter = bpf_map_lookup_elem(&count_map, &key);
  if (counter != NULL){

    *counter+= 1;
    bpf_trace_printk("key exit, updating value", 25);
    bpf_map_update_elem(&count_map, &key, counter, 0);
  }else {
    bpf_trace_printk("key not exist, add value", 25);
    __u32 val =1;
    bpf_map_update_elem(&count_map, &key, &val,0);
  }

  return 0;
}
