/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _DCP_THREAD_H_
#define _DCP_THREAD_H_

#include <pthread.h>
#include <stdint.h>

#include <linux/if_ether.h>

#include "thread.h"

int dcp_threads_create(struct thread_context *thread_context);
void dcp_threads_free(struct thread_context *thread_context);
void dcp_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _DCP_THREAD_H_ */
