# Architecture

## Data path

KernWatch has two trust and execution domains.

1. **eBPF programs** attach to stable tracepoint names for `execve`, process exit, `openat`, and `connect`.
2. **libbpf userspace** loads and attaches the CO-RE object, configures maps, polls the ring buffer, applies the optional command filter, and serializes events as NDJSON.

The build produces `vmlinux.h` from `/sys/kernel/btf/vmlinux` and uses libbpf CO-RE relocations instead of compiling against a copied kernel source tree.

## Maps

### `config`

A one-entry array map contains the runtime PID/UID filter configuration and the open-event capture toggle. PID and UID checks happen before a ring-buffer reservation.

### `events`

A bounded BPF ring buffer transfers fixed-size `kw_event` records. Kernel code never allocates variable-sized event records.

### `stats`

A per-CPU one-entry array records ring-buffer reservation failures. Per-CPU storage avoids contended atomic updates in the hot path. Userspace sums the counters at shutdown.

## Event semantics

The event schema intentionally distinguishes observation from outcome:

- `exec` is emitted at `sys_enter_execve`; it does not prove the image was successfully executed.
- `open` is emitted at `sys_enter_openat`; it does not prove the file was opened.
- `connect` is emitted at `sys_enter_connect`; it does not prove a connection was established.
- `exit` is emitted at `sched_process_exit`.

Future milestones can pair entry/exit events when outcome semantics are needed.

## Failure model

A full ring buffer can cause event loss. KernWatch counts failed reservations, but it cannot reconstruct dropped events.

If the kernel rejects the BPF object because of missing features, verifier constraints, lockdown, LSM policy, or insufficient privilege, the userspace loader fails closed and exits. It never silently falls back to `/proc` polling.

## Portability

CO-RE reduces kernel-structure coupling. It does not guarantee support for every distribution or security policy. The first milestone builds on x86_64 and arm64 host architecture mappings; broader compatibility requires measured CI evidence.
