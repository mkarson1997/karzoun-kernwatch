#include "format.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int append_char(char *buffer, size_t capacity, size_t *used, char value)
{
    if (*used + 1 >= capacity) {
        return -ENOSPC;
    }
    buffer[*used] = value;
    *used += 1;
    buffer[*used] = '\0';
    return 0;
}

static int append_text(char *buffer, size_t capacity, size_t *used, const char *text)
{
    size_t length = strlen(text);
    if (*used + length >= capacity) {
        return -ENOSPC;
    }
    memcpy(buffer + *used, text, length);
    *used += length;
    buffer[*used] = '\0';
    return 0;
}

static int append_json_string(char *buffer, size_t capacity, size_t *used, const char *text)
{
    int rc = append_char(buffer, capacity, used, '"');
    if (rc != 0) {
        return rc;
    }

    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; cursor++) {
        char escaped[7] = {0};
        const char *replacement = NULL;

        switch (*cursor) {
        case '"':
            replacement = "\\\"";
            break;
        case '\\':
            replacement = "\\\\";
            break;
        case '\b':
            replacement = "\\b";
            break;
        case '\f':
            replacement = "\\f";
            break;
        case '\n':
            replacement = "\\n";
            break;
        case '\r':
            replacement = "\\r";
            break;
        case '\t':
            replacement = "\\t";
            break;
        default:
            if (*cursor < 0x20U) {
                (void)snprintf(escaped, sizeof(escaped), "\\u%04x", *cursor);
                replacement = escaped;
            }
            break;
        }

        if (replacement != NULL) {
            rc = append_text(buffer, capacity, used, replacement);
        } else {
            rc = append_char(buffer, capacity, used, (char)*cursor);
        }

        if (rc != 0) {
            return rc;
        }
    }

    return append_char(buffer, capacity, used, '"');
}

static const char *event_name(__u32 type)
{
    switch (type) {
    case KW_EVENT_EXEC:
        return "exec";
    case KW_EVENT_EXIT:
        return "exit";
    case KW_EVENT_CONNECT:
        return "connect";
    case KW_EVENT_OPEN:
        return "open";
    default:
        return "unknown";
    }
}

int kw_event_matches_comm(const struct kw_event *event, const char *comm)
{
    if (event == NULL) {
        return 0;
    }
    if (comm == NULL || comm[0] == '\0') {
        return 1;
    }
    return strncmp(event->comm, comm, KW_COMM_LEN) == 0;
}

int kw_format_event(const struct kw_event *event, char *buffer, size_t capacity)
{
    if (event == NULL || buffer == NULL || capacity == 0) {
        return -EINVAL;
    }

    buffer[0] = '\0';
    size_t used = 0;
    char scratch[256];

    int written = snprintf(
        scratch,
        sizeof(scratch),
        "{\"schema\":1,\"type\":\"%s\",\"ts_ns\":%llu,\"pid\":%u,\"tid\":%u,"
        "\"ppid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":",
        event_name(event->type),
        (unsigned long long)event->ts_ns,
        event->pid,
        event->tid,
        event->ppid,
        event->uid,
        event->gid);

    if (written < 0 || (size_t)written >= sizeof(scratch)) {
        return -EIO;
    }

    int rc = append_text(buffer, capacity, &used, scratch);
    if (rc != 0) {
        return rc;
    }

    rc = append_json_string(buffer, capacity, &used, event->comm);
    if (rc != 0) {
        return rc;
    }

    if (event->type == KW_EVENT_EXEC || event->type == KW_EVENT_OPEN) {
        rc = append_text(buffer, capacity, &used, ",\"path\":");
        if (rc != 0) {
            return rc;
        }
        rc = append_json_string(buffer, capacity, &used, event->path);
        if (rc != 0) {
            return rc;
        }
    } else if (event->type == KW_EVENT_EXIT) {
        written = snprintf(scratch, sizeof(scratch), ",\"exit_code\":%d", event->value);
        if (written < 0 || (size_t)written >= sizeof(scratch)) {
            return -EIO;
        }
        rc = append_text(buffer, capacity, &used, scratch);
        if (rc != 0) {
            return rc;
        }
    } else if (event->type == KW_EVENT_CONNECT) {
        char address[INET6_ADDRSTRLEN] = "unknown";
        const void *source = event->daddr;
        int address_family = event->family == 2U ? AF_INET :
            (event->family == 10U ? AF_INET6 : AF_UNSPEC);

        if (address_family != AF_UNSPEC &&
            inet_ntop(address_family, source, address, sizeof(address)) == NULL) {
            (void)snprintf(address, sizeof(address), "unprintable");
        }

        written = snprintf(
            scratch,
            sizeof(scratch),
            ",\"family\":%u,\"dst\":",
            (unsigned int)event->family);
        if (written < 0 || (size_t)written >= sizeof(scratch)) {
            return -EIO;
        }
        rc = append_text(buffer, capacity, &used, scratch);
        if (rc != 0) {
            return rc;
        }
        rc = append_json_string(buffer, capacity, &used, address);
        if (rc != 0) {
            return rc;
        }

        written = snprintf(scratch, sizeof(scratch), ",\"dport\":%u", (unsigned int)event->dport);
        if (written < 0 || (size_t)written >= sizeof(scratch)) {
            return -EIO;
        }
        rc = append_text(buffer, capacity, &used, scratch);
        if (rc != 0) {
            return rc;
        }
    }

    rc = append_char(buffer, capacity, &used, '}');
    if (rc != 0) {
        return rc;
    }

    return (int)used;
}
