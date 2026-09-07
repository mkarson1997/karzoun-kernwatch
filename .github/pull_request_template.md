## What changed

Describe the kernel/userspace behavior changed by this pull request.

## Evidence

- [ ] `make test`
- [ ] `make sanitize`
- [ ] CO-RE object + skeleton + userspace agent build on Linux
- [ ] CI Gate is green
- [ ] CodeQL is green

## Kernel-safety review

- [ ] BPF loops and memory access remain verifier-friendly
- [ ] User pointers are accessed only through BPF probe-read helpers
- [ ] Event/path sizes remain bounded
- [ ] No new enforcement/blocking behavior is implied without explicit design and tests
