/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _UDP_THREAD_H_
#define _UDP_THREAD_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pthread.h>

#include "stat.h"
#include "thread.h"

int udp_low_threads_create(struct thread_context *thread_context);
void udp_low_threads_free(struct thread_context *thread_context);
void udp_low_threads_wait_for_finish(struct thread_context *thread_context);

int udp_high_threads_create(struct thread_context *thread_context);
void udp_high_threads_free(struct thread_context *thread_context);
void udp_high_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _UDP_THREAD_H_ */
