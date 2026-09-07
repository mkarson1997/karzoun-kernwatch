#ifndef KERNWATCH_H
#define KERNWATCH_H

#include <linux/types.h>

#define KW_COMM_LEN 16
#define KW_PATH_LEN 256

enum kw_event_type {
    KW_EVENT_EXEC = 1,
    KW_EVENT_EXIT = 2,
    KW_EVENT_CONNECT = 3,
    KW_EVENT_OPEN = 4,
};

struct kw_config {
    __u32 uid;
    __u32 pid;
    __u8 filter_uid;
    __u8 filter_pid;
    __u8 capture_open;
    __u8 reserved;
};

struct kw_event {
    __u64 ts_ns;
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __s32 value;
    __u16 family;
    __u16 dport;
    __u8 daddr[16];
    char comm[KW_COMM_LEN];
    char path[KW_PATH_LEN];
};

#endif
