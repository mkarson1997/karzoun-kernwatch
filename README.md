# Karzoun KernWatch

[![CI](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/codeql.yml/badge.svg)](https://github.com/mkarson1997/karzoun-kernwatch/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

KernWatch is a Linux eBPF telemetry agent written in C. The v0.1 foundation observes a deliberately bounded set of kernel events and streams them to userspace as newline-delimited JSON (NDJSON).

It is **not an EDR**, does not block activity, and does not claim threat detection. The current goal is to make kernel telemetry collection, filtering, transport, and failure accounting explicit and testable.

## v0.1 telemetry

KernWatch attaches tracepoint programs for:

- process execution (`execve`)
- process exit
- outbound `connect(2)` calls for IPv4 and IPv6
- `openat(2)` file-open attempts

Events move from eBPF to userspace through a BPF ring buffer. Kernel-side filters can restrict collection by PID or UID, while an optional exact command-name filter runs in userspace.

The stable event envelope includes schema version, monotonic kernel timestamp, PID/TID/PPID, UID/GID, command name and event-specific fields. Paths are bounded to 255 bytes plus a terminator.

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
{"schema":1,"type":"connect","ts_ns":123456789,"pid":4242,"tid":4242,"ppid":1000,"uid":1000,"gid":1000,"comm":"curl","family":2,"dst":"127.0.0.1","dport":443}
```

KernWatch prints the accumulated ring-buffer reserve-failure count to stderr at shutdown.

## Design boundaries

- This release captures telemetry only. It does not enforce policy.
- `connect(2)` records attempts at syscall entry, not confirmed TCP establishment.
- `openat(2)` records requested paths, not successful opens.
- command-name filtering is performed in userspace; PID/UID filters run before ring-buffer reservation.
- pathname capture is intentionally bounded.
- ring-buffer pressure is observable through a per-CPU reserve-failure counter.
- kernel feature and security-policy differences can prevent program loading even when compilation succeeds.

See [Architecture](docs/architecture.md), [Security](SECURITY.md) and [Roadmap](ROADMAP.md).

## License

Apache-2.0.
