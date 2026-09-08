#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "format.h"
#include "kernwatch.h"
#include "kernwatch.skel.h"

#ifndef KW_VERSION
#define KW_VERSION "0.1.0-dev"
#endif

static volatile sig_atomic_t stop_requested = 0;

struct runtime_options {
    struct kw_config config;
    char comm[KW_COMM_LEN];
    int poll_ms;
};

static void on_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int parse_u32(const char *text, __u32 *value)
{
    if (text == NULL || value == NULL || text[0] == '\0') {
        return -EINVAL;
    }

    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT_MAX) {
        return -EINVAL;
    }

    *value = (__u32)parsed;
    return 0;
}

static int parse_positive_int(const char *text, int *value)
{
    __u32 parsed = 0;
    int rc = parse_u32(text, &parsed);
    if (rc != 0 || parsed == 0 || parsed > 60000U) {
        return -EINVAL;
    }
    *value = (int)parsed;
    return 0;
}

static void print_usage(FILE *stream, const char *program)
{
    fprintf(
        stream,
        "Usage: %s [--uid UID] [--pid PID] [--comm NAME] [--no-open] [--poll-ms N]\n"
        "\n"
        "Streams Linux kernel telemetry as NDJSON.\n"
        "  --uid UID      kernel-side UID filter\n"
        "  --pid PID      kernel-side process-ID filter\n"
        "  --comm NAME    userspace exact command-name filter (max 15 bytes)\n"
        "  --no-open      disable openat file-open events\n"
        "  --poll-ms N    ring-buffer poll timeout, 1..60000 (default 250)\n"
        "  --version      print build version and exit\n"
        "  --help         show this help\n",
        program);
}

static int parse_options(int argc, char **argv, struct runtime_options *options)
{
    static const struct option long_options[] = {
        {"uid", required_argument, NULL, 'u'},
        {"pid", required_argument, NULL, 'p'},
        {"comm", required_argument, NULL, 'c'},
        {"no-open", no_argument, NULL, 'o'},
        {"poll-ms", required_argument, NULL, 'm'},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    memset(options, 0, sizeof(*options));
    options->config.capture_open = 1;
    options->poll_ms = 250;

    int option = 0;
    while ((option = getopt_long(argc, argv, "u:p:c:om:Vh", long_options, NULL)) != -1) {
        switch (option) {
        case 'u':
            if (parse_u32(optarg, &options->config.uid) != 0) {
                fprintf(stderr, "invalid --uid value\n");
                return -EINVAL;
            }
            options->config.filter_uid = 1;
            break;
        case 'p':
            if (parse_u32(optarg, &options->config.pid) != 0 || options->config.pid == 0) {
                fprintf(stderr, "invalid --pid value\n");
                return -EINVAL;
            }
            options->config.filter_pid = 1;
            break;
        case 'c':
            if (strlen(optarg) >= sizeof(options->comm)) {
                fprintf(stderr, "--comm must be at most %zu bytes\n", sizeof(options->comm) - 1);
                return -EINVAL;
            }
            (void)snprintf(options->comm, sizeof(options->comm), "%s", optarg);
            break;
        case 'o':
            options->config.capture_open = 0;
            break;
        case 'm':
            if (parse_positive_int(optarg, &options->poll_ms) != 0) {
                fprintf(stderr, "invalid --poll-ms value\n");
                return -EINVAL;
            }
            break;
        case 'V':
            printf("kernwatch %s\n", KW_VERSION);
            return 1;
        case 'h':
            print_usage(stdout, argv[0]);
            return 1;
        default:
            print_usage(stderr, argv[0]);
            return -EINVAL;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "unexpected positional argument: %s\n", argv[optind]);
        return -EINVAL;
    }

    return 0;
}

static int handle_event(void *context, void *data, size_t data_size)
{
    const struct runtime_options *options = context;

    if (data_size < sizeof(struct kw_event)) {
        fprintf(stderr, "received truncated kernel event: %zu bytes\n", data_size);
        return 0;
    }

    const struct kw_event *event = data;
    if (!kw_event_matches_comm(event, options->comm)) {
        return 0;
    }

    char line[1024];
    int rc = kw_format_event(event, line, sizeof(line));
    if (rc < 0) {
        fprintf(stderr, "failed to format event: %d\n", rc);
        return 0;
    }

    puts(line);
    return 0;
}

static void configure_libbpf_logging(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
}

static void raise_memlock_limit(void)
{
    const struct rlimit limit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0 && errno != EPERM) {
        fprintf(stderr, "warning: unable to raise RLIMIT_MEMLOCK: %s\n", strerror(errno));
    }
}

static unsigned long long read_drop_count(int map_fd)
{
    __u32 key = 0;
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) {
        return 0;
    }

    __u64 *values = calloc((size_t)cpu_count, sizeof(*values));
    if (values == NULL) {
        return 0;
    }

    unsigned long long total = 0;
    if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
        for (int i = 0; i < cpu_count; i++) {
            total += values[i];
        }
    }

    free(values);
    return total;
}

int main(int argc, char **argv)
{
    struct runtime_options options;
    int rc = parse_options(argc, argv, &options);
    if (rc == 1) {
        return EXIT_SUCCESS;
    }
    if (rc != 0) {
        return EXIT_FAILURE;
    }

    configure_libbpf_logging();
    raise_memlock_limit();

    if (signal(SIGINT, on_signal) == SIG_ERR || signal(SIGTERM, on_signal) == SIG_ERR) {
        perror("signal");
        return EXIT_FAILURE;
    }

    struct kernwatch_bpf *skeleton = kernwatch_bpf__open();
    if (skeleton == NULL) {
        fprintf(stderr, "failed to open KernWatch BPF skeleton\n");
        return EXIT_FAILURE;
    }

    rc = kernwatch_bpf__load(skeleton);
    if (rc != 0) {
        fprintf(stderr, "failed to load BPF programs: %d\n", rc);
        kernwatch_bpf__destroy(skeleton);
        return EXIT_FAILURE;
    }

    __u32 key = 0;
    int config_fd = bpf_map__fd(skeleton->maps.kw_config_map);
    if (bpf_map_update_elem(config_fd, &key, &options.config, BPF_ANY) != 0) {
        perror("bpf_map_update_elem(kw_config_map)");
        kernwatch_bpf__destroy(skeleton);
        return EXIT_FAILURE;
    }

    rc = kernwatch_bpf__attach(skeleton);
    if (rc != 0) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", rc);
        kernwatch_bpf__destroy(skeleton);
        return EXIT_FAILURE;
    }

    struct ring_buffer *ring = ring_buffer__new(
        bpf_map__fd(skeleton->maps.kw_events),
        handle_event,
        &options,
        NULL);
    if (ring == NULL) {
        fprintf(stderr, "failed to create ring buffer\n");
        kernwatch_bpf__destroy(skeleton);
        return EXIT_FAILURE;
    }

    while (!stop_requested) {
        rc = ring_buffer__poll(ring, options.poll_ms);
        if (rc == -EINTR) {
            continue;
        }
        if (rc < 0) {
            fprintf(stderr, "ring-buffer poll failed: %d\n", rc);
            break;
        }
    }

    unsigned long long dropped = read_drop_count(bpf_map__fd(skeleton->maps.kw_stats));
    fprintf(stderr, "kernwatch: dropped_events=%llu\n", dropped);

    ring_buffer__free(ring);
    kernwatch_bpf__destroy(skeleton);

    return rc < 0 && rc != -EINTR ? EXIT_FAILURE : EXIT_SUCCESS;
}
