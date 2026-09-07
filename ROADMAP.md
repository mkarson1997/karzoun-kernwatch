# Roadmap

## v0.1 - telemetry foundation

- CO-RE build + libbpf skeleton
- exec/exit/connect/open telemetry
- BPF ring buffer
- PID/UID kernel filters
- userspace command filter
- NDJSON output
- reserve-failure accounting
- strict CI, sanitizers, CodeQL
- real privileged load/attach smoke with exec/connect assertions

## v0.2 - stronger event semantics

- syscall outcome correlation for open/connect
- explicit parent-process and exit-status semantics without fabricated fields
- cgroup and mount-namespace metadata
- monotonic sequence identifiers
- configurable event sampling and per-event enablement
- measured event-throughput/overhead benchmarks

## v0.3 - detection primitives

Only after telemetry semantics are proven:

- explicit rule engine
- bounded state maps
- rule attribution in events
- replayable userspace test fixtures
- detection-quality measurements

## Not promised

KernWatch does not call itself an EDR, anti-malware product, or prevention platform unless future releases actually implement and validate those capabilities.
