# Contributing

1. Open an issue for behavior changes.
2. Work on a branch.
3. Keep kernel event semantics explicit.
4. Run `make test` and `make sanitize`.
5. Build the CO-RE object, generated skeleton, and userspace loader on Linux.
6. Keep compiler warnings enabled and do not weaken CI to make a change pass.

For BPF changes, document why memory access is verifier-safe and how event volume remains bounded. Do not introduce enforcement or detection claims without corresponding semantics and tests.
