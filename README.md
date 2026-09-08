# Karzoun KernWatch

[![CI](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/ci.yml)
[![Runtime smoke](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/runtime-smoke.yml/badge.svg)](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/runtime-smoke.yml)
[![CodeQL](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/codeql.yml/badge.svg)](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/codeql.yml)
[![Userspace license](https://img.shields.io/badge/userspace-Apache--2.0-blue.svg)](LICENSE)
[![eBPF license](https://img.shields.io/badge/eBPF-GPL--2.0--only-blue.svg)](LICENSES/GPL-2.0-only.txt)

KernWatch is a Linux eBPF telemetry agent written in C. The v0.1 foundation observes a deliberately bounded set of kernel events and streams them to userspace as newline-delimited JSON (NDJSON).

It is **not an EDR**, does not block activity, and does not claim threat detection. The current goal is to make kernel telemetry collection, filtering, transport, and failure accounting explicit and testable.

## v0.1 telemetry

KernWatch attaches tracepoint programs for:

- process execution attempts (`execve`)
- process exit observation
- outbound `connect(2)` calls for IPv4 and IPv6
- `openat(2)` file-open attempts

Events move from eBPF to userspace through a BPF ring buffer. Kernel-side filters can restrict collection by PID or UID, while an optional exact command-name filter runs in userspace.

The event envelope includes schema version, monotonic kernel timestamp, PID/TID, UID/GID, command name and event-specific fields. Paths are bounded to 255 bytes plus a terminator. v0.1 deliberately does not fabricate parent-process or exit-status data it has not proven.

## Build requirements

KernWatch currently targets Linux hosts with:

- kernel BTF exposed at `/sys/kernel/btf/vmlinux`
- BPF ring-buffer support
- Clang/LLVM
- `bpftool` from the distribution's Linux tools package
- libbpf development headers
- libelf + zlib
- GNU Make
- a C17 compiler

On Ubuntu 24.04, `bpftool` is provided through the Linux tools packages rather than a directly installable `bpftool` package:

```bash
sudo apt-get update
sudo apt-get install -y linux-tools-common linux-tools-generic clang llvm \
  libbpf-dev libelf-dev zlib1g-dev pkg-config
make all
make test
make sanitize
```

The Makefile first tries a working `bpftool` on `PATH`, then falls back to the newest real binary under `/usr/lib/linux-tools`. This avoids depending on a version-specific wrapper matching the running CI kernel exactly.

The build generates `vmlinux.h` from the running kernel BTF, compiles the CO-RE BPF object, generates a libbpf skeleton, and links the userspace agent.

## Run

Loading eBPF programs requires privileges allowed by the host kernel/security policy. Root is the simplest development setup:

```bash
sudo ./build/kernwatch
```

Examples:

```bash
sudo ./build/kernwatch --uid 1000
sudo ./build/kernwatch --pid 4242
sudo ./build/kernwatch --comm curl --no-open
```

Sample shape:

```json
{"schema":1,"type":"connect","ts_ns":123456789,"pid":4242,"tid":4242,"uid":1000,"gid":1000,"comm":"curl","family":2,"dst":"127.0.0.1","dport":443}
```

KernWatch prints the accumulated ring-buffer reserve-failure count to stderr at shutdown.

## Runtime evidence

The dedicated privileged smoke workflow performs a real load/attach on an Ubuntu 24.04 GitHub-hosted VM, triggers process execution and a localhost TCP connection, parses the emitted NDJSON, and verifies graceful SIGTERM shutdown. This is separate from the compile/security gate so kernel-host policy remains explicit.

## Design boundaries

- This release captures telemetry only. It does not enforce policy.
- `execve`, `connect(2)`, and `openat(2)` are observed at syscall entry and therefore do not prove success.
- `exit` observes `sched_process_exit` but v0.1 does not report an exit status or termination reason.
- command-name filtering is performed in userspace; PID/UID filters run before ring-buffer reservation.
- pathname capture is intentionally bounded.
- ring-buffer pressure is observable through a per-CPU reserve-failure counter.
- kernel feature and security-policy differences can prevent program loading even when compilation succeeds.

See [Architecture](docs/architecture.md), [Security](SECURITY.md) and [Roadmap](ROADMAP.md).

## License

Unless a file states otherwise, KernWatch is Apache-2.0. The kernel eBPF program in `bpf/kernwatch.bpf.c` is GPL-2.0-only and declares `GPL` to the Linux kernel because its tracing path uses GPL-restricted BPF helpers. See `LICENSE` and `LICENSES/GPL-2.0-only.txt`.
