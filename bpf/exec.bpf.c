//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_ARGS 20
#define ARGSIZE  128

char LICENSE[] SEC("license") = "GPL";

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[ARGSIZE];
    int argc;
    char argv[MAX_ARGS][ARGSIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename;
    const char *const *argv;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename = (const char *)ctx->args[0];
    argv = (const char *const *)ctx->args[1];

    bpf_probe_read_user_str(
        e->filename,
        sizeof(e->filename),
        filename);

    e->argc = 0;

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;

        if (bpf_probe_read_user(
                &argp,
                sizeof(argp),
                &argv[i]))
            break;

        if (!argp)
            break;

        if (bpf_probe_read_user_str(
                e->argv[i],
                ARGSIZE,
                argp) < 0)
            break;

        e->argc++;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
