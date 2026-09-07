#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "format.h"

static struct kw_event base_event(__u32 type)
{
    struct kw_event event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.ts_ns = 42;
    event.pid = 100;
    event.tid = 101;
    event.uid = 1000;
    event.gid = 1000;
    (void)snprintf(event.comm, sizeof(event.comm), "curl");
    return event;
}

static void test_exec_json_escaping(void)
{
    struct kw_event event = base_event(KW_EVENT_EXEC);
    (void)snprintf(event.path, sizeof(event.path), "/tmp/a\"b\\c");

    char buffer[1024];
    int rc = kw_format_event(&event, buffer, sizeof(buffer));

    assert(rc > 0);
    assert(strstr(buffer, "\"type\":\"exec\"") != NULL);
    assert(strstr(buffer, "\"path\":\"/tmp/a\\\"b\\\\c\"") != NULL);
}

static void test_connect_ipv4(void)
{
    struct kw_event event = base_event(KW_EVENT_CONNECT);
    event.family = 2;
    event.dport = 443;
    assert(inet_pton(AF_INET, "127.0.0.1", event.daddr) == 1);

    char buffer[1024];
    int rc = kw_format_event(&event, buffer, sizeof(buffer));

    assert(rc > 0);
    assert(strstr(buffer, "\"dst\":\"127.0.0.1\"") != NULL);
    assert(strstr(buffer, "\"dport\":443") != NULL);
}

static void test_exit_does_not_fabricate_status(void)
{
    struct kw_event event = base_event(KW_EVENT_EXIT);

    char buffer[1024];
    int rc = kw_format_event(&event, buffer, sizeof(buffer));

    assert(rc > 0);
    assert(strstr(buffer, "\"type\":\"exit\"") != NULL);
    assert(strstr(buffer, "exit_code") == NULL);
    assert(strstr(buffer, "ppid") == NULL);
}

static void test_comm_filter(void)
{
    struct kw_event event = base_event(KW_EVENT_OPEN);

    assert(kw_event_matches_comm(&event, "") == 1);
    assert(kw_event_matches_comm(&event, "curl") == 1);
    assert(kw_event_matches_comm(&event, "bash") == 0);
}

static void test_small_buffer_is_rejected(void)
{
    struct kw_event event = base_event(KW_EVENT_EXEC);
    (void)snprintf(event.path, sizeof(event.path), "/bin/echo");

    char buffer[8];
    assert(kw_format_event(&event, buffer, sizeof(buffer)) < 0);
}

int main(void)
{
    test_exec_json_escaping();
    test_connect_ipv4();
    test_exit_does_not_fabricate_status();
    test_comm_filter();
    test_small_buffer_is_rejected();

    puts("format tests: ok");
    return 0;
}
