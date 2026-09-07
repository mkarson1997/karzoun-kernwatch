# Security Policy

## Supported version

Security fixes target the latest `main` branch and the latest published release once releases exist.

## Reporting

Please use GitHub's private vulnerability reporting feature when available. Do not publish exploit details in a public issue before a fix is available.

## Security properties in v0.1

KernWatch keeps the kernel/userspace boundary deliberately small:

- eBPF events are fixed-size and bounded.
- user-space pointers are read with BPF probe-read helpers.
- path capture has a hard maximum length.
- PID/UID filtering happens before ring-buffer allocation.
- libbpf load/attach failures stop startup.
- no event is used to block, kill, rewrite, or redirect a process.
- no arbitrary kernel memory is exposed to userspace.
- the agent does not collect file contents, environment blocks, process memory, or packet payloads.

## Privilege

Loading BPF programs is a privileged operation whose exact capability requirements vary by kernel and distribution. Run only on systems you administer or are authorized to observe.

KernWatch is an observability tool, not a sandbox or security boundary.
