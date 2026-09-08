# Contributing

1. Open an issue for behavior changes.
2. Work on a branch.
3. Keep kernel event semantics explicit.
4. Run `make test` and `make sanitize`.
5. Build the CO-RE object, generated skeleton, and userspace loader on Linux.
6. Run `sudo bash scripts/runtime-smoke.sh` on an authorized BPF-capable Linux host when changing kernel/runtime behavior.
7. Keep compiler warnings enabled and do not weaken CI to make a change pass.

For BPF changes, document why memory access is verifier-safe and how event volume remains bounded. Do not introduce enforcement or detection claims without corresponding semantics and tests.

The repository is Apache-2.0 by default. Changes to `bpf/kernwatch.bpf.c` are GPL-2.0-only and must preserve its SPDX identifier and kernel `GPL` declaration because the program uses GPL-restricted tracing helpers.
