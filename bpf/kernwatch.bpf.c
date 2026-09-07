#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "kernwatch.h"

char LICENSE[] SEC("license") = "Apache-2.0";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} kw_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kw_config);
} kw_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} kw_stats SEC(".maps");

struct kw_sockaddr_in {
    __u16 family;
    __be16 port;
    __be32 addr;
};

struct kw_sockaddr_in6 {
    __u16 family;
    __be16 port;
    __be32 flowinfo;
    __u8 addr[16];
    __u32 scope_id;
};

static __always_inline const struct kw_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&kw_config_map, &key);
}

static __always_inline int event_allowed(__u32 pid, __u32 uid)
{
    const struct kw_config *cfg = get_config();
    if (cfg == NULL) {
        return 1;
    }
    if (cfg->filter_pid && cfg->pid != pid) {
        return 0;
    }
    if (cfg->filter_uid && cfg->uid != uid) {
        return 0;
    }
    return 1;
}

static __always_inline void record_drop(void)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&kw_stats, &key);
    if (count != NULL) {
        *count += 1;
    }
}

static __always_inline struct kw_event *new_event(__u32 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)uid_gid;

    if (!event_allowed(pid, uid)) {
        return NULL;
    }

    struct kw_event *event = bpf_ringbuf_reserve(&kw_events, sizeof(*event), 0);
    if (event == NULL) {
        record_drop();
        return NULL;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->ts_ns = bpf_ktime_get_ns();
    event->type = type;
    event->pid = pid;
    event->tid = (__u32)pid_tgid;
    event->uid = uid;
    event->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task != NULL) {
        event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    }

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    return event;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct kw_event *event = new_event(KW_EVENT_EXEC);
    if (event == NULL) {
        return 0;
    }

    const char *filename = (const char *)ctx->args[0];
    (void)bpf_probe_read_user_str(event->path, sizeof(event->path), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(void *ctx)
{
    (void)ctx;

    struct kw_event *event = new_event(KW_EVENT_EXIT);
    if (event == NULL) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task != NULL) {
        int exit_code = BPF_CORE_READ(task, exit_code);
        event->value = exit_code >> 8;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const struct kw_config *cfg = get_config();
    if (cfg != NULL && !cfg->capture_open) {
        return 0;
    }

    struct kw_event *event = new_event(KW_EVENT_OPEN);
    if (event == NULL) {
        return 0;
    }

    const char *filename = (const char *)ctx->args[1];
    (void)bpf_probe_read_user_str(event->path, sizeof(event->path), filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    const void *user_addr = (const void *)ctx->args[1];
    __u16 family = 0;

    if (bpf_probe_read_user(&family, sizeof(family), user_addr) != 0) {
        return 0;
    }

    if (family != 2 && family != 10) {
        return 0;
    }

    struct kw_event *event = new_event(KW_EVENT_CONNECT);
    if (event == NULL) {
        return 0;
    }

    event->family = family;

    if (family == 2) {
        struct kw_sockaddr_in address = {};
        if (bpf_probe_read_user(&address, sizeof(address), user_addr) == 0) {
            event->dport = bpf_ntohs(address.port);
            __builtin_memcpy(event->daddr, &address.addr, sizeof(address.addr));
        }
    } else {
        struct kw_sockaddr_in6 address6 = {};
        if (bpf_probe_read_user(&address6, sizeof(address6), user_addr) == 0) {
            event->dport = bpf_ntohs(address6.port);
            __builtin_memcpy(event->daddr, address6.addr, sizeof(address6.addr));
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
