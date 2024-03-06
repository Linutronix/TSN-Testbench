/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RTA_THREAD_H_
#define _RTA_THREAD_H_

#include <pthread.h>
#include <stdint.h>

#include "thread.h"
#include "xdp.h"

#define RTA_TX_FRAME_LENGTH XDP_FRAME_SIZE

int rta_threads_create(struct thread_context *thread_context);
void rta_threads_stop(struct thread_context *thread_context);
void rta_threads_free(struct thread_context *thread_context);
void rta_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _RTA_THREAD_H_ */
