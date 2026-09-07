#ifndef KERNWATCH_FORMAT_H
#define KERNWATCH_FORMAT_H

#include <stddef.h>

#include "kernwatch.h"

int kw_event_matches_comm(const struct kw_event *event, const char *comm);
int kw_format_event(const struct kw_event *event, char *buffer, size_t capacity);

#endif
