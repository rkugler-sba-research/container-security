//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    const char *filename = (const char *)ctx->args[0];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();

    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(
        &e->filename,
        sizeof(e->filename),
        filename
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}